package oapigen

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type ObsMode uint8

const (
	ObsDisable ObsMode = 0
	ObsEnable  ObsMode = 1
)

const (
	defaultContentType  = "application/octet-stream"
	formURLEncoded      = "application/x-www-form-urlencoded"
	mimeApplicationJSON = "application/json"
)

type HeaderObject = map[string]any

type Config struct {
	Title          string
	Version        string
	ServerURL      string // ex: "http://localhost:3000"
	JSONPath       string // ex: "/openapi.json"
	DocsPath       string // ex: "/docs"
	SpecFile       string // ex: "openapi.json"
	Observe        ObsMode
	ExcludeMethod  []string
	RoutesProvider func() []Route // optional provider for static routes
}

type Route struct {
	Method string
	Path   string
}

type CaptureContext struct {
	Method              string
	Path                string
	RoutePattern        string
	QueryParams         url.Values
	RequestHeaders      http.Header
	RequestBody         []byte
	RequestContentType  string
	ResponseHeaders     http.Header
	ResponseBody        []byte
	ResponseContentType string
	Status              int
}

type Middleware struct {
	Cfg Config

	// in-memory spec (thread-safe)
	spec     map[string]any
	Mu       sync.RWMutex
	SpecJSON []byte

	// observation by route/method
	obsMu sync.Mutex
	obs   map[string]*observed // key = METHOD+" "+normalizedPath

	excludeMethod map[string]bool

	routesOnce     sync.Once
	routesProvider func() []Route
}

type (
	observed struct {
		ReqContents map[string]*contentCapture
		ReqHeaders  []oasParam
		Res         map[int]*responseCapture
		Params      []oasParam
		Tags        []string
		Sum         string
		Desc        string
	}

	responseCapture struct {
		Contents map[string]*contentCapture
		Headers  map[string]HeaderObject
	}

	contentCapture struct {
		Schema   map[string]any
		Examples []exampleCapture
		JSON     *jsonPresence
	}

	payloadSample struct {
		ContentType string
		Schema      map[string]any
		Example     any
		ExampleKey  string
	}

	exampleCapture struct {
		Key   string
		Value any
	}

	oasParam struct {
		Name     string
		In       string // "query" | "path" | "header"
		Required bool
		Schema   map[string]any
		Example  any
	}
)

var noisyHeaders = map[string]struct{}{
	"accept": {}, "accept-encoding": {}, "connection": {},
	"content-length": {}, "host": {}, "user-agent": {},
	"upgrade-insecure-requests": {},
}

// New middleware instance
func New(cfgs ...Config) *Middleware {
	var cfg Config
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	if cfg.Title == "" {
		cfg.Title = "API"
	}
	if cfg.Version == "" {
		cfg.Version = "1.0.0"
	}
	if cfg.JSONPath == "" {
		cfg.JSONPath = "/openapi.json"
	}
	if cfg.DocsPath == "" {
		cfg.DocsPath = "/docs"
	}
	if cfg.SpecFile == "" {
		cfg.SpecFile = "/docs/openapi.json"
	}
	exclude := map[string]bool{}
	for _, mth := range cfg.ExcludeMethod {
		if nm := strings.ToUpper(strings.TrimSpace(mth)); nm != "" {
			exclude[nm] = true
		}
	}
	m := &Middleware{
		Cfg:           cfg,
		obs:           make(map[string]*observed),
		excludeMethod: exclude,
	}
	m.SetRoutesProvider(cfg.RoutesProvider)
	return m
}

// ---------- public helpers (optional enrich) ----------

func (m *Middleware) SetRoutesProvider(fn func() []Route) {
	if fn == nil {
		return
	}
	m.routesOnce.Do(func() {
		m.routesProvider = fn
	})
}

func (m *Middleware) Tag(path, method string, tags ...string) {
	key := keyOf(method, path)
	m.obsMu.Lock()
	defer m.obsMu.Unlock()
	o := ensureObs(m.obs, key)
	o.Tags = append(o.Tags, tags...)
}

func (m *Middleware) Summary(path, method, text string) {
	key := keyOf(method, path)
	m.obsMu.Lock()
	defer m.obsMu.Unlock()
	o := ensureObs(m.obs, key)
	o.Sum = text
}

func (m *Middleware) Description(path, method, text string) {
	key := keyOf(method, path)
	m.obsMu.Lock()
	defer m.obsMu.Unlock()
	o := ensureObs(m.obs, key)
	o.Desc = text
}

func (m *Middleware) Capture(ctx CaptureContext) {
	if m.Cfg.Observe == ObsDisable {
		return
	}

	method := strings.ToUpper(strings.TrimSpace(ctx.Method))
	if method == "" {
		return
	}
	if m.isMethodExcluded(method) {
		return
	}

	routePattern := strings.TrimSpace(ctx.RoutePattern)
	if routePattern == "" {
		routePattern = strings.TrimSpace(ctx.Path)
	}
	if routePattern == "" {
		return
	}

	npath := normalize(routePattern)
	key := keyOf(method, npath)

	reqBody := payloadSampleFrom(ctx.RequestBody, ctx.RequestContentType)
	resBody := payloadSampleFrom(ctx.ResponseBody, ctx.ResponseContentType)
	queryParams := queryParamsToParams(ctx.QueryParams)
	pathParams := pathParamsFromPattern(routePattern)
	params := mergeParams(queryParams, pathParams)
	reqHeaders := requestHeadersToParams(ctx.RequestHeaders)
	resHeaders := responseHeadersToHeaderObjects(ctx.ResponseHeaders)

	status := ctx.Status
	if status == 0 {
		status = http.StatusOK
	}

	if reqBody == nil && resBody == nil && len(params) == 0 && len(reqHeaders) == 0 && len(resHeaders) == 0 {
		return
	}

	m.obsMu.Lock()
	o := ensureObs(m.obs, key)
	if reqBody != nil {
		addContentSample(o.ReqContents, reqBody)
	}
	if len(params) > 0 {
		o.Params = mergeParams(o.Params, params)
	}
	if len(reqHeaders) > 0 {
		o.ReqHeaders = mergeParams(o.ReqHeaders, reqHeaders)
	}
	if resBody != nil {
		resp := ensureResponseCapture(o.Res, status)
		addContentSample(resp.Contents, resBody)
		if len(resHeaders) > 0 {
			resp.Headers = mergeHeaderObjects(resp.Headers, resHeaders)
		}
	} else if len(resHeaders) > 0 {
		resp := ensureResponseCapture(o.Res, status)
		resp.Headers = mergeHeaderObjects(resp.Headers, resHeaders)
	}
	m.obsMu.Unlock()

	m.rebuildAndPersist()
}

func (m *Middleware) EnsureSpecInitialized() {
	m.Mu.RLock()
	ok := m.spec != nil
	m.Mu.RUnlock()
	if ok {
		return
	}
	m.rebuildAndPersist()
}

// ---------- spec build/persist ----------

func (m *Middleware) rebuildAndPersist() {
	// base spec (original)
	var base map[string]any
	if b, err := os.ReadFile(m.Cfg.SpecFile); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &base)
	}
	if base == nil {
		base = map[string]any{}
	}

	// spec routes + observations
	newSpec := m.buildBaseSpec()
	m.applyObservations(newSpec)
	m.applyInfoServer(newSpec)

	// merge: override
	spec := mergeAnyMap(base, newSpec)

	data, _ := json.MarshalIndent(spec, "", "  ")

	// swap in-memory
	m.Mu.Lock()
	unchanged := len(m.SpecJSON) > 0 && bytes.Equal(m.SpecJSON, data)
	m.spec = spec
	m.SpecJSON = data
	m.Mu.Unlock()

	if unchanged {
		if info, err := os.Stat(m.Cfg.SpecFile); err == nil && !info.IsDir() {
			return
		}
	}

	// ensure dir exists
	dir := filepath.Dir(m.Cfg.SpecFile)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Printf("[fiberopenapi] mkdir %s error: %v\n", dir, err)
		}
	}
	if err := os.WriteFile(m.Cfg.SpecFile, data, 0o644); err != nil {
		fmt.Printf("[fiberopenapi] write %s error: %v\n", m.Cfg.SpecFile, err)
	}
}

func (m *Middleware) buildBaseSpec() map[string]any {
	paths := map[string]any{}

	if m.routesProvider != nil {
		allow := map[string]bool{
			http.MethodGet:     true,
			http.MethodPost:    true,
			http.MethodPut:     true,
			http.MethodPatch:   true,
			http.MethodDelete:  true,
			http.MethodOptions: true,
			http.MethodHead:    true,
		}
		type kv struct {
			method string
			path   string
		}
		var list []kv
		for _, r := range m.routesProvider() {
			if r.Path == m.Cfg.JSONPath || r.Path == m.Cfg.DocsPath {
				continue
			}
			if r.Path == "" || r.Method == "" {
				continue
			}
			upper := strings.ToUpper(r.Method)
			if !allow[upper] || m.isMethodExcluded(upper) {
				continue
			}
			list = append(list, kv{
				method: strings.ToLower(r.Method),
				path:   normalize(r.Path),
			})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].path == list[j].path {
				return list[i].method < list[j].method
			}
			return list[i].path < list[j].path
		})
		for _, it := range list {
			methods, ok := paths[it.path].(map[string]any)
			if !ok {
				methods = map[string]any{}
				paths[it.path] = methods
			}
			if _, exists := methods[it.method]; !exists {
				methods[it.method] = map[string]any{
					"responses": map[string]any{
						"200": map[string]any{"description": http.StatusText(http.StatusOK)},
					},
				}
			}
		}
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]any{},
		"servers": []map[string]any{},
		"paths":   paths,
	}
}

func (m *Middleware) applyInfoServer(spec map[string]any) {
	spec["info"] = map[string]any{
		"title":   m.Cfg.Title,
		"version": m.Cfg.Version,
	}
	if m.Cfg.ServerURL != "" {
		spec["servers"] = []map[string]any{{"url": m.Cfg.ServerURL}}
	}
}

func (m *Middleware) applyObservations(spec map[string]any) {
	paths := spec["paths"].(map[string]any)

	m.obsMu.Lock()
	defer m.obsMu.Unlock()

	for key, o := range m.obs {
		method, path := splitKey(key)

		// ensure path map
		methods, ok := paths[path].(map[string]any)
		if !ok {
			methods = map[string]any{}
			paths[path] = methods
		}

		// ensure operation map
		lower := strings.ToLower(method)
		op, _ := methods[lower].(map[string]any)
		if op == nil {
			op = map[string]any{}
			methods[lower] = op
		}

		// tags/summary/description
		if len(o.Tags) > 0 {
			op["tags"] = unique(o.Tags)
		}
		if o.Sum != "" {
			op["summary"] = o.Sum
		}
		if o.Desc != "" {
			op["description"] = o.Desc
		}

		// parameters (query/path + header)
		if len(o.Params) > 0 || len(o.ReqHeaders) > 0 {
			ps := make([]any, 0, len(o.Params)+len(o.ReqHeaders))
			for _, p := range append(o.Params, o.ReqHeaders...) {
				obj := map[string]any{
					"name":     p.Name,
					"in":       p.In,
					"required": p.Required,
					"schema":   p.Schema,
				}
				if p.Example != nil {
					obj["example"] = p.Example
				}
				ps = append(ps, obj)
			}
			op["parameters"] = ps
		}

		// requestBody
		if len(o.ReqContents) > 0 {
			content := map[string]any{}
			for ct, cap := range o.ReqContents {
				if obj := buildContentObject(cap); len(obj) > 0 {
					content[ct] = obj
				}
			}
			if len(content) > 0 {
				op["requestBody"] = map[string]any{
					"required": true,
					"content":  content,
				}
			}
		}

		// responses (merge)
		resp := map[string]any{}
		if old, ok := op["responses"].(map[string]any); ok {
			for k, v := range old {
				resp[k] = v
			}
		}
		for code, capture := range o.Res {
			entry := map[string]any{
				"description": http.StatusText(code),
			}
			if len(capture.Contents) > 0 {
				content := map[string]any{}
				for ct, cap := range capture.Contents {
					if obj := buildContentObject(cap); len(obj) > 0 {
						content[ct] = obj
					}
				}
				if len(content) > 0 {
					entry["content"] = content
				}
			}
			if len(capture.Headers) > 0 {
				entry["headers"] = capture.Headers
			}
			resp[fmt.Sprintf("%d", code)] = entry
		}
		if len(resp) == 0 {
			resp["200"] = map[string]any{"description": http.StatusText(http.StatusOK)}
		}
		op["responses"] = resp
	}
}

// ---------- utils: key, normalize, (de)type ----------

func keyOf(method, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.ToUpper(method) + " " + normalize(path)
}

func splitKey(key string) (method, path string) {
	i := strings.IndexByte(key, ' ')
	return key[:i], key[i+1:]
}

func normalize(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if strings.HasPrefix(seg, ":") && len(seg) > 1 {
			parts[i] = "{" + seg[1:] + "}"
		} else if strings.HasPrefix(seg, "*") && len(seg) > 1 {
			parts[i] = "{" + seg[1:] + "}"
		}
	}
	out := strings.Join(parts, "/")
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return out
}

func unique(ss []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// ---------- schema inference & merge ----------

func inferJSONSchema(b []byte) map[string]any {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return schemaFromValue(v)
}

func schemaFromValue(v any) map[string]any {
	switch x := v.(type) {
	case nil:
		return map[string]any{"type": "null"}
	case bool:
		return map[string]any{"type": "boolean"}
	case float64:
		// JSON numbers
		return map[string]any{"type": "number"}
	case string:
		return map[string]any{"type": "string"}
	case []any:
		if len(x) == 0 {
			return map[string]any{"type": "array", "items": map[string]any{}}
		}
		// all schema
		item := schemaFromValue(x[0])
		for i := 1; i < len(x); i++ {
			item = mergeSchema(item, schemaFromValue(x[i]))
		}
		return map[string]any{"type": "array", "items": item}
	case map[string]any:
		props := map[string]any{}
		for k, vv := range x {
			props[k] = schemaFromValue(vv)
		}
		return map[string]any{"type": "object", "properties": props}
	default:
		// fallback othor
		return map[string]any{"type": "string"}
	}
}

func mergeSchema(a, b map[string]any) map[string]any {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	ta, _ := a["type"].(string)
	tb, _ := b["type"].(string)

	// object
	if ta == "object" && tb == "object" {
		propsA, _ := a["properties"].(map[string]any)
		propsB, _ := b["properties"].(map[string]any)
		props := map[string]any{}
		for k, v := range propsA {
			props[k] = v
		}
		for k, v := range propsB {
			if old, ok := props[k].(map[string]any); ok {
				props[k] = mergeSchema(old, v.(map[string]any))
			} else {
				props[k] = v
			}
		}
		return map[string]any{"type": "object", "properties": props}
	}

	// array
	if ta == "array" && tb == "array" {
		ia, _ := a["items"].(map[string]any)
		ib, _ := b["items"].(map[string]any)
		return map[string]any{"type": "array", "items": mergeSchema(ia, ib)}
	}

	return anyOf(a, b)
}

func anyOf(schemas ...map[string]any) map[string]any {
	seen := map[string]struct{}{}
	arr := make([]any, 0, len(schemas))
	for _, s := range schemas {
		if s == nil {
			continue
		}
		js, _ := json.Marshal(s)
		key := string(js)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		arr = append(arr, s)
	}
	if len(arr) == 1 {
		return arr[0].(map[string]any)
	}
	return map[string]any{"anyOf": arr}
}

func guessScalarSchema(val string) map[string]any {
	l := strings.ToLower(val)
	if l == "true" || l == "false" {
		return map[string]any{"type": "boolean"}
	}
	if _, err := fmt.Sscan(val, new(float64)); err == nil {
		return map[string]any{"type": "number"}
	}
	return map[string]any{"type": "string"}
}

func mergeParams(a, b []oasParam) []oasParam {
	out := make([]oasParam, 0, len(a)+len(b))
	out = append(out, a...)
	// dedup by (name,in)
	index := map[string]int{}
	for i, p := range out {
		index[p.In+"|"+p.Name] = i
	}
	for _, p := range b {
		k := p.In + "|" + p.Name
		if i, ok := index[k]; ok {
			// merge schema
			out[i].Schema = mergeSchema(out[i].Schema, p.Schema)
			out[i].Required = out[i].Required || p.Required
			if out[i].Example == nil && p.Example != nil {
				out[i].Example = p.Example
			}
			continue
		}
		index[k] = len(out)
		out = append(out, p)
	}
	return out
}

func addContentSample(dst map[string]*contentCapture, sample *payloadSample) {
	if sample == nil {
		return
	}
	ct := sample.ContentType
	if ct == "" {
		return
	}
	cap := ensureContentCapture(dst, ct)
	if sample.Schema != nil {
		cap.Schema = mergeSchema(cap.Schema, sample.Schema)
	}
	if sample.Example != nil && sample.ExampleKey != "" {
		cap.Examples = appendExample(cap.Examples, exampleCapture{
			Key:   sample.ExampleKey,
			Value: sample.Example,
		})
	}
	cap.recordJSONPresence(sample.Example)
}

func ensureContentCapture(m map[string]*contentCapture, ct string) *contentCapture {
	if cap, ok := m[ct]; ok && cap != nil {
		return cap
	}
	cap := &contentCapture{
		Schema:   nil,
		Examples: nil,
	}
	m[ct] = cap
	return cap
}

func ensureResponseCapture(m map[int]*responseCapture, status int) *responseCapture {
	if cap, ok := m[status]; ok && cap != nil {
		return cap
	}
	cap := &responseCapture{
		Contents: map[string]*contentCapture{},
		Headers:  map[string]HeaderObject{},
	}
	m[status] = cap
	return cap
}

func appendExample(list []exampleCapture, ex exampleCapture) []exampleCapture {
	if ex.Key == "" || ex.Value == nil {
		return list
	}
	for _, existing := range list {
		if existing.Key == ex.Key {
			return list
		}
	}
	return append(list, ex)
}

func (cap *contentCapture) recordJSONPresence(example any) {
	obj, ok := example.(map[string]any)
	if !ok {
		return
	}
	if cap.JSON == nil {
		cap.JSON = newJSONPresence()
	}
	cap.JSON.observeObject(obj)
}

type jsonPresence struct {
	Total  int
	Fields map[string]*jsonFieldPresence
}

type jsonFieldPresence struct {
	Present int
	NonNull int
	Object  *jsonPresence
}

func newJSONPresence() *jsonPresence {
	return &jsonPresence{
		Fields: map[string]*jsonFieldPresence{},
	}
}

func (p *jsonPresence) observeObject(obj map[string]any) {
	if p == nil {
		return
	}
	p.Total++
	if p.Fields == nil {
		p.Fields = map[string]*jsonFieldPresence{}
	}
	for name, val := range obj {
		field := p.ensureField(name)
		field.Present++
		if val != nil {
			field.NonNull++
		}
		switch v := val.(type) {
		case map[string]any:
			if field.Object == nil {
				field.Object = newJSONPresence()
			}
			field.Object.observeObject(v)
		case []any:
			for _, item := range v {
				imap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if field.Object == nil {
					field.Object = newJSONPresence()
				}
				field.Object.observeObject(imap)
			}
		}
	}
}

func (p *jsonPresence) ensureField(name string) *jsonFieldPresence {
	if p.Fields == nil {
		p.Fields = map[string]*jsonFieldPresence{}
	}
	if f, ok := p.Fields[name]; ok && f != nil {
		return f
	}
	f := &jsonFieldPresence{}
	p.Fields[name] = f
	return f
}

func (p *jsonPresence) field(name string) *jsonFieldPresence {
	if p == nil || p.Fields == nil {
		return nil
	}
	return p.Fields[name]
}

func applyJSONRequired(schema map[string]any, presence *jsonPresence) {
	if schema == nil {
		return
	}

	if anyOf, ok := schema["anyOf"].([]any); ok {
		for _, sub := range anyOf {
			if subSchema, ok := sub.(map[string]any); ok {
				applyJSONRequired(subSchema, presence)
			}
		}
	}
	if allOf, ok := schema["allOf"].([]any); ok {
		for _, sub := range allOf {
			if subSchema, ok := sub.(map[string]any); ok {
				applyJSONRequired(subSchema, presence)
			}
		}
	}
	if oneOf, ok := schema["oneOf"].([]any); ok {
		for _, sub := range oneOf {
			if subSchema, ok := sub.(map[string]any); ok {
				applyJSONRequired(subSchema, presence)
			}
		}
	}

	typ, _ := schema["type"].(string)
	switch typ {
	case "object":
		props, _ := schema["properties"].(map[string]any)
		if len(props) == 0 {
			return
		}
		if presence != nil && presence.Total > 0 {
			required := make([]string, 0, len(props))
			for name := range props {
				field := presence.field(name)
				if field != nil && field.Present == presence.Total && field.NonNull == presence.Total {
					required = append(required, name)
				}
			}
			if len(required) > 0 {
				sort.Strings(required)
				schema["required"] = required
			} else {
				delete(schema, "required")
			}
		}
		for name, prop := range props {
			propSchema, ok := prop.(map[string]any)
			if !ok {
				continue
			}
			var childPresence *jsonPresence
			if presence != nil {
				if field := presence.field(name); field != nil {
					childPresence = field.Object
				}
			}
			applyJSONRequired(propSchema, childPresence)
		}
	case "array":
		if items, ok := schema["items"].(map[string]any); ok {
			applyJSONRequired(items, presence)
		}
	}
}

func payloadSampleFrom(body []byte, header string) *payloadSample {
	if len(body) == 0 {
		return nil
	}
	raw := strings.TrimSpace(header)
	ct := baseContentType(raw)
	if ct == "" {
		ct = defaultContentType
	}
	if raw == "" {
		raw = ct
	}
	schema, example, key := schemaAndExampleForBody(ct, raw, body)
	if schema == nil && example == nil {
		return nil
	}
	return &payloadSample{
		ContentType: ct,
		Schema:      schema,
		Example:     example,
		ExampleKey:  key,
	}
}

func queryParamsToParams(values url.Values) []oasParam {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var params []oasParam
	for _, name := range keys {
		vals := values[name]
		if len(vals) == 0 {
			params = append(params, oasParam{
				Name:     name,
				In:       "query",
				Required: false,
				Schema:   map[string]any{"type": "string"},
				Example:  "",
			})
			continue
		}
		if len(vals) == 1 {
			params = append(params, oasParam{
				Name:     name,
				In:       "query",
				Required: false,
				Schema:   guessScalarSchema(vals[0]),
				Example:  parseScalarValue(vals[0]),
			})
			continue
		}
		item := guessScalarSchema(vals[0])
		for i := 1; i < len(vals); i++ {
			item = mergeSchema(item, guessScalarSchema(vals[i]))
		}
		example := make([]any, 0, len(vals))
		for _, v := range vals {
			example = append(example, parseScalarValue(v))
		}
		params = append(params, oasParam{
			Name:     name,
			In:       "query",
			Required: false,
			Schema: map[string]any{
				"type":  "array",
				"items": item,
			},
			Example: example,
		})
	}
	return params
}

func pathParamsFromPattern(pattern string) []oasParam {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var params []oasParam
	for _, seg := range strings.Split(pattern, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		var name string
		switch {
		case strings.HasPrefix(seg, ":") && len(seg) > 1:
			name = seg[1:]
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2:
			name = seg[1 : len(seg)-1]
		}
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		params = append(params, oasParam{
			Name:     name,
			In:       "path",
			Required: true,
			Schema:   map[string]any{"type": "string"},
		})
	}
	return params
}

func requestHeadersToParams(headers http.Header) []oasParam {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []oasParam
	for _, name := range keys {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		if _, noisy := noisyHeaders[lower]; noisy {
			continue
		}
		values := headers[name]
		if len(values) == 0 {
			continue
		}
		raw := strings.TrimSpace(values[0])
		masked := maskHeaderValue(name, raw)
		out = append(out, oasParam{
			Name:     name,
			In:       "header",
			Required: false,
			Schema:   guessScalarSchema(masked),
			Example:  parseScalarValue(masked),
		})
	}
	return out
}

func responseHeadersToHeaderObjects(headers http.Header) map[string]HeaderObject {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]HeaderObject{}
	for _, name := range keys {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		if _, noisy := noisyHeaders[lower]; noisy {
			continue
		}
		values := headers[name]
		if len(values) == 0 {
			continue
		}
		for _, val := range values {
			raw := strings.TrimSpace(val)
			masked := maskHeaderValue(name, raw)
			if existing, ok := out[name]; ok {
				if sch, _ := existing["schema"].(map[string]any); sch != nil {
					existing["schema"] = mergeSchema(sch, guessScalarSchema(masked))
				}
				if existing["example"] == nil {
					existing["example"] = parseScalarValue(masked)
				} else if ex := existing["example"]; ex != masked {
					exmap, _ := existing["examples"].(map[string]any)
					if exmap == nil {
						exmap = map[string]any{}
					}
					exmap[fmt.Sprintf("ex%d", len(exmap)+1)] = map[string]any{"value": parseScalarValue(masked)}
					existing["examples"] = exmap
				}
				out[name] = existing
				continue
			}
			out[name] = HeaderObject{
				"schema":  guessScalarSchema(masked),
				"example": parseScalarValue(masked),
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func schemaAndExampleForBody(contentType, header string, body []byte) (map[string]any, any, string) {
	if len(body) == 0 {
		return nil, nil, ""
	}
	if strings.HasPrefix(contentType, "multipart/") {
		if schema, example, key := schemaAndExampleForMultipart(contentType, header, body); schema != nil || example != nil {
			return schema, example, key
		}
	}
	switch {
	case isJSONContentType(contentType):
		if schema := inferJSONSchema(body); schema != nil {
			var example any
			if err := json.Unmarshal(body, &example); err != nil {
				example = string(body)
			}
			return schema, example, contentType + ":" + string(bytes.TrimSpace(body))
		}
	case contentType == formURLEncoded:
		values, err := url.ParseQuery(string(body))
		if err == nil {
			schema := schemaFromFormValues(values)
			example := exampleFromFormValues(values)
			return schema, example, contentType + ":" + string(body)
		}
		return map[string]any{"type": "string"}, string(body), contentType + ":" + string(body)
	case strings.HasPrefix(contentType, "text/"):
		return map[string]any{"type": "string"}, string(body), contentType + ":" + string(body)
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	return map[string]any{
		"type":   "string",
		"format": "binary",
	}, encoded, contentType + ":" + encoded
}

func schemaAndExampleForMultipart(contentType, header string, body []byte) (map[string]any, any, string) {
	if header == "" {
		return nil, nil, ""
	}
	_, params, err := mime.ParseMediaType(header)
	if err != nil {
		return nil, nil, ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil, ""
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	values := url.Values{}
	fileParts := map[string][][]byte{}
	partCount := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, ""
		}

		payload, err := io.ReadAll(part)
		if err != nil {
			return nil, nil, ""
		}
		partCount++

		name := part.FormName()
		if name == "" {
			name = part.FileName()
		}
		if name == "" {
			name = fmt.Sprintf("part_%d", partCount)
		}

		if part.FileName() != "" {
			fileParts[name] = append(fileParts[name], payload)
			continue
		}
		values.Add(name, string(payload))
	}

	if len(values) == 0 && len(fileParts) == 0 {
		return nil, nil, ""
	}

	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
	props := schema["properties"].(map[string]any)
	example := map[string]any{}

	if len(values) > 0 {
		fieldSchema := schemaFromFormValues(values)
		if fieldProps, ok := fieldSchema["properties"].(map[string]any); ok {
			for k, v := range fieldProps {
				props[k] = v
			}
		}
		fieldExample := exampleFromFormValues(values)
		for k, v := range fieldExample {
			example[k] = v
		}
	}

	for name, files := range fileParts {
		props[name] = schemaFromFileSlices(files)
		example[name] = exampleFromFileSlices(files)
	}

	var exampleValue any
	if len(example) > 0 {
		exampleValue = example
	}

	encoded := base64.StdEncoding.EncodeToString(body)
	return schema, exampleValue, contentType + ":" + encoded
}

func schemaFromFileSlices(files [][]byte) map[string]any {
	if len(files) <= 1 {
		return map[string]any{
			"type":   "string",
			"format": "binary",
		}
	}
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":   "string",
			"format": "binary",
		},
	}
}

func exampleFromFileSlices(files [][]byte) any {
	if len(files) == 0 {
		return ""
	}
	if len(files) == 1 {
		return base64.StdEncoding.EncodeToString(files[0])
	}
	arr := make([]any, len(files))
	for i, f := range files {
		arr[i] = base64.StdEncoding.EncodeToString(f)
	}
	return arr
}

func schemaFromFormValues(values url.Values) map[string]any {
	props := map[string]any{}
	for key, val := range values {
		props[key] = schemaFromFormSlice(val)
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
	}
}

func schemaFromFormSlice(values []string) map[string]any {
	switch len(values) {
	case 0:
		return map[string]any{"type": "string"}
	case 1:
		return guessScalarSchema(values[0])
	default:
		item := guessScalarSchema(values[0])
		for i := 1; i < len(values); i++ {
			item = mergeSchema(item, guessScalarSchema(values[i]))
		}
		return map[string]any{
			"type":  "array",
			"items": item,
		}
	}
}

func exampleFromFormValues(values url.Values) map[string]any {
	out := map[string]any{}
	for key, val := range values {
		if len(val) == 0 {
			out[key] = ""
			continue
		}
		if len(val) == 1 {
			out[key] = parseScalarValue(val[0])
			continue
		}
		arr := make([]any, 0, len(val))
		for _, v := range val {
			arr = append(arr, parseScalarValue(v))
		}
		out[key] = arr
	}
	return out
}

func baseContentType(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ";")
	base := strings.TrimSpace(strings.ToLower(parts[0]))
	return base
}

func isJSONContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	if contentType == mimeApplicationJSON {
		return true
	}
	if strings.HasSuffix(contentType, "+json") {
		return true
	}
	if strings.HasSuffix(contentType, "/json") {
		return true
	}
	return false
}

func buildContentObject(cap *contentCapture) map[string]any {
	if cap == nil {
		return map[string]any{}
	}
	obj := map[string]any{}
	if cap.Schema != nil {
		applyJSONRequired(cap.Schema, cap.JSON)
		obj["schema"] = cap.Schema
	}
	switch len(cap.Examples) {
	case 0:
	case 1:
		obj["example"] = cap.Examples[0].Value
	default:
		examples := map[string]any{}
		for i, ex := range cap.Examples {
			examples[fmt.Sprintf("ex%d", i+1)] = map[string]any{"value": ex.Value}
		}
		obj["examples"] = examples
	}
	return obj
}

func ensureObs(m map[string]*observed, key string) *observed {
	if o, ok := m[key]; ok && o != nil {
		return o
	}
	o := &observed{
		ReqContents: map[string]*contentCapture{},
		Res:         map[int]*responseCapture{},
		Params:      []oasParam{},
		Tags:        []string{},
		Sum:         "",
		Desc:        "",
	}
	m[key] = o
	return o
}

func mergeAnyMap(base, overlay map[string]any) map[string]any {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}
	out := make(map[string]any, len(base))
	for k, v := range base {
		out[k] = v
	}
	for k, v2 := range overlay {
		if v1, ok := out[k]; ok {
			map1, ok1 := v1.(map[string]any)
			map2, ok2 := v2.(map[string]any)
			if ok1 && ok2 {
				out[k] = mergeAnyMap(map1, map2)
				continue
			}
		}
		out[k] = v2
	}
	return out
}

func parseScalarValue(s string) any {
	ls := strings.ToLower(strings.TrimSpace(s))
	if ls == "true" || ls == "false" {
		return ls == "true"
	}
	var f float64
	if _, err := fmt.Sscan(s, &f); err == nil {
		return f
	}
	return s
}

func maskHeaderValue(name, val string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "authorization":
		if strings.HasPrefix(strings.ToLower(val), "bearer ") {
			return "Bearer ****"
		}
		return "****"
	case "cookie", "set-cookie":
		parts := strings.Split(val, ";")
		for i := range parts {
			kv := strings.SplitN(strings.TrimSpace(parts[i]), "=", 2)
			if len(kv) == 2 {
				parts[i] = kv[0] + "=****"
			}
		}
		return strings.Join(parts, "; ")
	default:
		return val
	}
}

func mergeHeaderObjects(dst, src map[string]HeaderObject) map[string]HeaderObject {
	if dst == nil {
		return src
	}
	if src == nil {
		return dst
	}

	out := make(map[string]HeaderObject, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}

	for k, v := range src {
		if cur, ok := out[k]; ok {
			if ds, _ := cur["schema"].(map[string]any); ds != nil {
				if ss, _ := v["schema"].(map[string]any); ss != nil {
					cur["schema"] = mergeSchema(ds, ss)
				}
			}
			if cur["example"] == nil && v["example"] != nil {
				cur["example"] = v["example"]
			} else if cur["example"] != nil && v["example"] != nil && cur["example"] != v["example"] {
				exmap, _ := cur["examples"].(map[string]any)
				if exmap == nil {
					exmap = map[string]any{}
				}
				exmap[fmt.Sprintf("ex%d", len(exmap)+1)] = map[string]any{"value": v["example"]}
				cur["examples"] = exmap
			}
			out[k] = cur
			continue
		}
		out[k] = v
	}
	return out
}

func (m *Middleware) isMethodExcluded(method string) bool {
	if len(m.excludeMethod) == 0 {
		return false
	}
	return m.excludeMethod[strings.ToUpper(method)]
}

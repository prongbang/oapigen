package oapigen

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSchemaAndExampleForBodyJSON(t *testing.T) {
	body := []byte(`{"name":"john","age":30}`)
	ct := "application/json"
	schema, example, key := schemaAndExampleForBody(ct, ct, body)

	expectedSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
			"age":  map[string]any{"type": "number"},
		},
	}
	if !reflect.DeepEqual(expectedSchema, schema) {
		t.Fatalf("unexpected schema\nexpected: %#v\nactual:   %#v", expectedSchema, schema)
	}

	expectedExample := map[string]any{
		"name": "john",
		"age":  float64(30),
	}
	if !reflect.DeepEqual(expectedExample, example) {
		t.Fatalf("unexpected example\nexpected: %#v\nactual:   %#v", expectedExample, example)
	}

	expectedKey := `application/json:{"name":"john","age":30}`
	if key != expectedKey {
		t.Fatalf("unexpected cache key, expected %q got %q", expectedKey, key)
	}
}

func TestSchemaAndExampleForBodyFormURLEncoded(t *testing.T) {
	body := []byte("name=alice&age=30&multi=1&multi=2")
	ct := "application/x-www-form-urlencoded"
	schema, example, key := schemaAndExampleForBody(ct, ct, body)

	props := map[string]any{
		"name": map[string]any{"type": "string"},
		"age":  map[string]any{"type": "number"},
		"multi": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "number",
			},
		},
	}
	expectedSchema := map[string]any{"type": "object", "properties": props}
	if !reflect.DeepEqual(expectedSchema, schema) {
		t.Fatalf("unexpected schema\nexpected: %#v\nactual:   %#v", expectedSchema, schema)
	}

	expectedExample := map[string]any{
		"name":  "alice",
		"age":   float64(30),
		"multi": []any{float64(1), float64(2)},
	}
	if !reflect.DeepEqual(expectedExample, example) {
		t.Fatalf("unexpected example\nexpected: %#v\nactual:   %#v", expectedExample, example)
	}

	expectedKey := ct + ":name=alice&age=30&multi=1&multi=2"
	if key != expectedKey {
		t.Fatalf("unexpected cache key, expected %q got %q", expectedKey, key)
	}
}

func TestSchemaAndExampleForBodyText(t *testing.T) {
	body := []byte("plain text value")
	header := "text/plain; charset=utf-8"
	schema, example, key := schemaAndExampleForBody("text/plain", header, body)

	expectedSchema := map[string]any{"type": "string"}
	if !reflect.DeepEqual(expectedSchema, schema) {
		t.Fatalf("unexpected schema\nexpected: %#v\nactual:   %#v", expectedSchema, schema)
	}
	expectedExample := "plain text value"
	if example != expectedExample {
		t.Fatalf("unexpected example, expected %q got %#v", expectedExample, example)
	}
	if key != "text/plain:plain text value" {
		t.Fatalf("unexpected cache key, got %q", key)
	}
}

func TestSchemaAndExampleForBodyBinary(t *testing.T) {
	body := []byte{0x00, 0x01, 0x02, 0x03}
	ct := "application/octet-stream"
	schema, example, key := schemaAndExampleForBody(ct, ct, body)

	expectedSchema := map[string]any{
		"type":   "string",
		"format": "binary",
	}
	if !reflect.DeepEqual(expectedSchema, schema) {
		t.Fatalf("unexpected schema\nexpected: %#v\nactual:   %#v", expectedSchema, schema)
	}

	expectedExample := base64.StdEncoding.EncodeToString(body)
	if example != expectedExample {
		t.Fatalf("unexpected example, expected %q got %#v", expectedExample, example)
	}

	expectedKey := ct + ":" + expectedExample
	if key != expectedKey {
		t.Fatalf("unexpected cache key, expected %q got %q", expectedKey, key)
	}
}

func TestSchemaAndExampleForMultipartMix(t *testing.T) {
	header, base, body := buildMultipartBody(t, func(w *multipart.Writer) {
		if err := w.WriteField("username", "alice"); err != nil {
			t.Fatalf("write field: %v", err)
		}
		part, err := w.CreateFormFile("avatar", "avatar.png")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		if _, err := part.Write([]byte("PNGDATA")); err != nil {
			t.Fatalf("write file: %v", err)
		}
	})

	schema, example, key := schemaAndExampleForBody(base, header, body)
	if !strings.HasPrefix(key, "multipart/form-data:") {
		t.Fatalf("unexpected cache key %q", key)
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing or wrong type: %#v", schema)
	}
	usernameSchema, ok := props["username"].(map[string]any)
	if !ok || !reflect.DeepEqual(usernameSchema, map[string]any{"type": "string"}) {
		t.Fatalf("unexpected username schema: %#v", usernameSchema)
	}

	avatarSchema, ok := props["avatar"].(map[string]any)
	expectedAvatarSchema := map[string]any{
		"type":   "string",
		"format": "binary",
	}
	if !ok || !reflect.DeepEqual(expectedAvatarSchema, avatarSchema) {
		t.Fatalf("unexpected avatar schema: %#v", avatarSchema)
	}

	exmap, ok := example.(map[string]any)
	if !ok {
		t.Fatalf("example should be map, got %#v", example)
	}
	if exmap["username"] != "alice" {
		t.Fatalf("unexpected username example: %#v", exmap["username"])
	}
	expectedAvatarExample := base64.StdEncoding.EncodeToString([]byte("PNGDATA"))
	if exmap["avatar"] != expectedAvatarExample {
		t.Fatalf("unexpected avatar example: %#v", exmap["avatar"])
	}
}

func TestSchemaAndExampleForMultipartMultipleFiles(t *testing.T) {
	fileContents := [][]byte{[]byte("file-one"), []byte("file-two")}
	header, base, body := buildMultipartBody(t, func(w *multipart.Writer) {
		for i, data := range fileContents {
			part, err := w.CreateFormFile("files", fmt.Sprintf("file-%d.txt", i))
			if err != nil {
				t.Fatalf("create file: %v", err)
			}
			if _, err := part.Write(data); err != nil {
				t.Fatalf("write file: %v", err)
			}
		}
	})

	schema, example, _ := schemaAndExampleForBody(base, header, body)

	props := schema["properties"].(map[string]any)
	filesSchema, ok := props["files"].(map[string]any)
	if !ok {
		t.Fatalf("files schema missing: %#v", schema)
	}
	if filesSchema["type"] != "array" {
		t.Fatalf("expected array schema, got %#v", filesSchema)
	}
	items, ok := filesSchema["items"].(map[string]any)
	expectedItems := map[string]any{"type": "string", "format": "binary"}
	if !ok || !reflect.DeepEqual(items, expectedItems) {
		t.Fatalf("unexpected items schema: %#v", items)
	}

	exmap := example.(map[string]any)
	rawFiles, ok := exmap["files"].([]any)
	if !ok || len(rawFiles) != len(fileContents) {
		t.Fatalf("unexpected files example: %#v", exmap["files"])
	}
	for i, raw := range rawFiles {
		expected := base64.StdEncoding.EncodeToString(fileContents[i])
		if raw != expected {
			t.Fatalf("unexpected file example at %d: got %#v want %q", i, raw, expected)
		}
	}
}

func TestInferredRequiredFieldsFromObservations(t *testing.T) {
	tmpDir := t.TempDir()
	specPath := filepath.Join(tmpDir, "spec.json")

	m := New(Config{
		JSONPath: "/openapi.json",
		DocsPath: "/docs",
		SpecFile: specPath,
		Observe:  ObsEnable,
	})

	baseCtx := CaptureContext{
		Method:             "POST",
		Path:               "/users",
		RoutePattern:       "/users",
		RequestContentType: "application/json",
		Status:             http.StatusOK,
	}

	first := baseCtx
	first.RequestBody = []byte(`{"name":"alice","age":30}`)
	m.Capture(first)

	second := baseCtx
	second.RequestBody = []byte(`{"name":"bob","age":null}`)
	m.Capture(second)

	third := baseCtx
	third.RequestBody = []byte(`{"name":"carol"}`)
	m.Capture(third)

	m.Mu.RLock()
	spec := m.spec
	m.Mu.RUnlock()

	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths missing or wrong type: %#v", spec["paths"])
	}
	pathItem, ok := paths["/users"].(map[string]any)
	if !ok {
		t.Fatalf("path item missing: %#v", paths)
	}
	postOp, ok := pathItem["post"].(map[string]any)
	if !ok {
		t.Fatalf("post operation missing: %#v", pathItem)
	}
	reqBody, ok := postOp["requestBody"].(map[string]any)
	if !ok {
		t.Fatalf("request body missing: %#v", postOp)
	}
	content, ok := reqBody["content"].(map[string]any)
	if !ok {
		t.Fatalf("content missing: %#v", reqBody)
	}
	appJSON, ok := content["application/json"].(map[string]any)
	if !ok {
		t.Fatalf("application/json entry missing: %#v", content)
	}
	schema, ok := appJSON["schema"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing: %#v", appJSON)
	}
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatalf("expected required to be []string, got %#v", schema["required"])
	}
	if len(required) != 1 || required[0] != "name" {
		t.Fatalf("unexpected required fields: %#v", required)
	}
	if _, ok := schema["properties"].(map[string]any)["age"]; !ok {
		t.Fatalf("age property missing from schema: %#v", schema["properties"])
	}
}

func TestCaptureStoresObservation(t *testing.T) {
	tmpDir := t.TempDir()
	specPath := filepath.Join(tmpDir, "openapi.json")

	m := New(Config{
		Title:    "Test",
		Version:  "1.0.0",
		JSONPath: "/openapi.json",
		DocsPath: "/docs",
		SpecFile: specPath,
		Observe:  ObsEnable,
	})

	m.Capture(CaptureContext{
		Method:       "POST",
		Path:         "/users/123",
		RoutePattern: "/users/:id",
		QueryParams:  url.Values{"active": {"true"}},
		RequestHeaders: http.Header{
			"Content-Type": {"application/json"},
		},
		RequestBody:         []byte(`{"name":"Alice"}`),
		RequestContentType:  "application/json",
		ResponseHeaders:     http.Header{"X-Request-Id": {"abc123"}},
		ResponseBody:        []byte(`{"id":1}`),
		ResponseContentType: "application/json",
		Status:              http.StatusCreated,
	})

	m.obsMu.Lock()
	obs := m.obs["POST /users/{id}"]
	m.obsMu.Unlock()
	if obs == nil {
		t.Fatalf("expected observation to be recorded")
	}
	if len(obs.ReqContents) == 0 {
		t.Fatalf("expected request contents to be stored")
	}
	if len(obs.Res) == 0 {
		t.Fatalf("expected response contents to be stored")
	}
	if _, err := os.Stat(specPath); err != nil {
		t.Fatalf("expected spec file to be written: %v", err)
	}
}

func TestBaseContentType(t *testing.T) {
	if got := baseContentType("application/json; charset=utf-8"); got != "application/json" {
		t.Fatalf("unexpected base content type: %q", got)
	}
	if got := baseContentType(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	if got := baseContentType("multipart/form-data; boundary=XYZ"); got != "multipart/form-data" {
		t.Fatalf("unexpected base content type: %q", got)
	}
}

func buildMultipartBody(t *testing.T, fn func(*multipart.Writer)) (header, base string, body []byte) {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	fn(writer)
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	header = writer.FormDataContentType()
	base = baseContentType(header)
	body = buf.Bytes()
	return
}

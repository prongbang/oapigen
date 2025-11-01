package oapigen

import "fmt"

type DocConfig struct {
	Title string
	JSONPath string
}

func NewScalar(cfg DocConfig) string {
	cdn := "https://cdnjs.cloudflare.com/ajax/libs/scalar-api-reference/1.35.5/standalone.js"
	html := fmt.Sprintf(`<!doctype html>
<html><head>
<meta charset="utf-8"/>
<title>%s</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>html,body,#scalar{height:100%%;margin:0;padding:0}</style>
<script src="%s"></script>
</head>
<body>
<div id="scalar"></div>
<script>
  Scalar.createApiReference('#scalar', {
    spec: { url: '%s' },
    layout: 'modern',
    theme: 'default',
    hideDownloadButton: false,
    hideClientButton: false
  });
</script>
</body>
</html>`, cfg.Title, cdn, cfg.JSONPath)
	return html
}

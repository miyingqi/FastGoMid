package FastGoMid

import (
	"os"

	fastgo "github.com/miyingqi/FastGo"
)

type SwaggerMid struct {
	Docs string
}

func NewSwaggerMid() *SwaggerMid {
	return &SwaggerMid{}
}

func (s *SwaggerMid) Handle(ctx *fastgo.Context) {
	if ctx.Path() == "/swagger/doc.json" {
		// 返回生成的 swagger.json
		ctx.SetHeader("Content-Type", "application/json")
		ctx.Data(200, "application/json", []byte(s.Docs))
		ctx.Abort()

		return
	}

	if ctx.Path() == "/swagger/" || ctx.Path() == "/swagger" {
		// 重定向到 index.html
		ctx.Redirect(302, "/swagger/index.html")
		ctx.Abort()

		return
	}

	if ctx.Path() == "/swagger/index.html" {
		ctx.SetHeader("Content-Type", "text/html")
		ctx.Data(200, "text/html", []byte(SwaggerIndexHTML))
		ctx.Abort()
		return
	}

	ctx.Next()
}

func (s *SwaggerMid) LoadSwaggerDoc(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		s.Docs = ""
	}
	s.Docs = string(file)
}

const SwaggerIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin: 0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: "/swagger/doc.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
            window.ui = ui;
        };
    </script>
</body>
</html>`

package cli

import "embed"

//go:embed templates/report.html
var reportTemplateFS embed.FS

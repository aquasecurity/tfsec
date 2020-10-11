package main

import (
	"fmt"
	"strings"
	"text/template"
)

const checksTableTemplate = `The {{$.Provider}} checks listed below have been implemented, for more information about each check, see the wiki link provided.

| Code  | Description | Wiki link |
|:-------|:-------------|:----------|
{{range $check := .Checks}}|{{$check.Code}}|{{$check.Description}}|[{{$check.Code}}](https://github.com/tfsec/tfsec/wiki/{{$check.Code}})|
{{end}}
`

func generateChecksFiles(registeredChecks []*FileContent) {
	for _, checkFileContent := range registeredChecks {
		generateCheckFile(checkFileContent)
	}
}

func generateCheckFile(checkFileContent *FileContent) {
	checkTmpl := template.Must(template.New("checks").Parse(checksTableTemplate))
	if err != nil {
		panic(err)

	}
	checksFilePath := fmt.Sprintf("%s/docs/%s_CHECKS.md", projectRoot, strings.ToUpper(checkFileContent.Provider))
	writeTemplate(checkFileContent, checksFilePath, checkTmpl)
	if generateWiki {
		providerFilePath := fmt.Sprintf("%s/%s/%s.md", wikiPath, strings.ToLower(checkFileContent.Provider), strings.ToUpper(checkFileContent.Provider))
		writeTemplate(checkFileContent, providerFilePath, checkTmpl)
	}
}

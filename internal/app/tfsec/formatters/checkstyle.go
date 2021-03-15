package formatters

import (
	"encoding/xml"
	"io"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type checkstyleResult struct {
	Rule     string `xml:"rule,attr"`
	Line     int    `xml:"line,attr"`
	Column   int    `xml:"column,attr"`
	Severity string `xml:"severity,attr"`
	Message  string `xml:"message,attr"`
	Link     string `xml:"link,attr"`
}

type checkstyleFile struct {
	Name   string             `xml:"name,attr"`
	Errors []checkstyleResult `xml:"error"`
}

type checkstyleOutput struct {
	XMLName xml.Name         `xml:"checkstyle"`
	Files   []checkstyleFile `xml:"file"`
}

func FormatCheckStyle(w io.Writer, results []scanner.Result, _ string, options ...FormatterOption) error {

	output := checkstyleOutput{}

	files := make(map[string][]checkstyleResult)

	// TODO - Handle if the --include-passed argument is passed.

	for _, result := range results {
		fileResults := append(
			files[result.Range.Filename],
			checkstyleResult{
				Rule:     string(result.RuleID),
				Line:     result.Range.StartLine,
				Severity: string(result.Severity),
				Message:  result.Description,
				Link:     result.Link,
			},
		)
		files[result.Range.Filename] = fileResults
	}

	for name, fileResults := range files {
		output.Files = append(
			output.Files,
			checkstyleFile{
				Name:   name,
				Errors: fileResults,
			},
		)
	}

	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}

	xmlEncoder := xml.NewEncoder(w)
	xmlEncoder.Indent("", "\t")

	return xmlEncoder.Encode(output)
}

package formatters

import (
	"encoding/xml"
	"io"

	"github.com/aquasecurity/tfsec/pkg/result"
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

func FormatCheckStyle(w io.Writer, results []result.Result, _ string, _ ...FormatterOption) error {

	output := checkstyleOutput{}

	files := make(map[string][]checkstyleResult)

	for _, res := range results {
		if res.Status == result.Passed {
			continue
		}
		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}
		fileResults := append(
			files[res.Range().Filename],
			checkstyleResult{
				Rule:     res.RuleID,
				Line:     res.Range().StartLine,
				Severity: string(res.Severity),
				Message:  res.Description,
				Link:     link,
			},
		)
		files[res.Range().Filename] = fileResults
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

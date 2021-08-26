package formatters

import (
	"encoding/xml"
	"io"

	"github.com/aquasecurity/defsec/rules"
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

func FormatCheckStyle(w io.Writer, results rules.Results, _ string, _ ...FormatterOption) error {

	output := checkstyleOutput{}

	files := make(map[string][]checkstyleResult)

	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			continue
		}
		var link string
		if len(res.Rule().Links) > 0 {
			link = res.Rule().Links[0]
		}
		fileResults := append(
			files[res.Metadata().Range().GetFilename()],
			checkstyleResult{
				Rule:     res.Rule().LongID(),
				Line:     res.Metadata().Range().GetStartLine(),
				Severity: string(res.Rule().Severity),
				Message:  res.Description(),
				Link:     link,
			},
		)
		files[res.Metadata().Range().GetFilename()] = fileResults
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

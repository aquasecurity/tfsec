package formatters

import (
	"encoding/xml"

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

func outputCheckStyle(b ConfigurableFormatter, results []rules.Result) error {

	output := checkstyleOutput{}

	files := make(map[string][]checkstyleResult)

	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			continue
		}
		var link string
		links := b.GetLinks(res)
		if len(links) > 0 {
			link = links[0]
		}

		rng := res.Range()

		files[rng.GetFilename()] = append(
			files[rng.GetFilename()],
			checkstyleResult{
				Rule:     res.Rule().LongID(),
				Line:     rng.GetStartLine(),
				Severity: string(res.Severity()),
				Message:  res.Description(),
				Link:     link,
			},
		)
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

	if _, err := b.Writer().Write([]byte(xml.Header)); err != nil {
		return err
	}

	xmlEncoder := xml.NewEncoder(b.Writer())
	xmlEncoder.Indent("", "\t")

	return xmlEncoder.Encode(output)
}

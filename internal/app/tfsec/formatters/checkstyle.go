package formatters

import (
	"encoding/xml"
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
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

func FormatCheckStyle(results []scanner.Result) error {

	output := checkstyleOutput{}

	files := make(map[string][]checkstyleResult)

	for _, result := range results {
		fileResults := append(
			files[result.Range.Filename],
			checkstyleResult{
				Rule:     string(result.RuleID),
				Line:     result.Range.StartLine,
				Severity: "warn",
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

	data, err := xml.MarshalIndent(output, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println(string(data))
	return nil
}

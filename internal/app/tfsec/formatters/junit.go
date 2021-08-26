package formatters

import (
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/rules"
)

// see https://github.com/windyroad/JUnit-Schema/blob/master/JUnit.xsd
// tested with CircleCI

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Failures  string          `xml:"failures,attr"`
	Tests     string          `xml:"tests,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

// JUnitFailure contains data related to a failed test.
type JUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

func FormatJUnit(w io.Writer, results rules.Results, _ string, options ...FormatterOption) error {

	output := JUnitTestSuite{
		Name:     "tfsec",
		Failures: fmt.Sprintf("%d", len(results)-countPassedResults(results)),
		Tests:    fmt.Sprintf("%d", len(results)),
	}

	for _, result := range results {
		output.TestCases = append(output.TestCases,
			JUnitTestCase{
				Classname: result.Metadata().Range().GetFilename(),
				Name:      fmt.Sprintf("[%s][%s] - %s", result.Rule().LongID(), result.Rule().Severity, result.Description()),
				Time:      "0",
				Failure:   buildFailure(result),
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

// highlight the lines of code which caused a problem, if available
func highlightCodeJunit(result rules.Result) string {

	data, err := ioutil.ReadFile(result.Metadata().Range().GetFilename())
	if err != nil {
		return ""
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	start := result.Metadata().Range().GetStartLine() - 3
	if start <= 0 {
		start = 1
	}
	end := result.Metadata().Range().GetEndLine() + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	output := ""

	for lineNo := start; lineNo <= end; lineNo++ {
		output += fmt.Sprintf("  % 6d | ", lineNo)
		if lineNo >= result.Metadata().Range().GetStartLine() && lineNo <= result.Metadata().Range().GetEndLine() {
			if lineNo == result.Metadata().Range().GetStartLine() && result.Annotation() != "" {
				output += fmt.Sprintf("%s    %s\n", lines[lineNo], result.Annotation())
			} else {
				output += fmt.Sprintf("%s\n", lines[lineNo])
			}
		} else {
			output += fmt.Sprintf("%s\n", lines[lineNo])
		}
	}

	return output
}

func buildFailure(res rules.Result) *JUnitFailure {
	if res.Status() == rules.StatusPassed {
		return nil
	}

	var link string
	if len(res.Rule().Links) > 0 {
		link = res.Rule().Links[0]
	}

	return &JUnitFailure{
		Message: res.Description(),
		Contents: fmt.Sprintf("%s\n%s\n%s",
			res.Metadata().Range().String(),
			highlightCodeJunit(res),
			link,
		),
	}
}

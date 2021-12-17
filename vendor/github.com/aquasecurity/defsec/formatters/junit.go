package formatters

import (
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
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

func FormatJUnit(w io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {

	output := JUnitTestSuite{
		Name:     filepath.Base(os.Args[0]),
		Failures: fmt.Sprintf("%d", len(results)-countPassedResults(results)),
		Tests:    fmt.Sprintf("%d", len(results)),
	}

	for _, res := range results {
		rng := res.NarrowestRange()
		output.TestCases = append(output.TestCases,
			JUnitTestCase{
				Classname: rng.GetFilename(),
				Name:      fmt.Sprintf("[%s][%s] - %s", res.Rule().LongID(), res.Severity(), res.Description()),
				Time:      "0",
				Failure:   buildFailure(res),
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
func highlightCodeJunit(res rules.Result) string {

	data, err := ioutil.ReadFile(res.NarrowestRange().GetFilename())
	if err != nil {
		return ""
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	rng := res.NarrowestRange()

	start := rng.GetStartLine() - 3
	if start <= 0 {
		start = 1
	}
	end := rng.GetEndLine() + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	output := ""

	for lineNo := start; lineNo <= end; lineNo++ {
		output += fmt.Sprintf("  % 6d | ", lineNo)
		if lineNo >= rng.GetStartLine() && lineNo <= rng.GetEndLine() {
			if lineNo == rng.GetStartLine() && res.Annotation() != "" {
				output += fmt.Sprintf("%s    %s\n", lines[lineNo], res.Annotation())
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
			res.NarrowestRange().String(),
			highlightCodeJunit(res),
			link,
		),
	}
}

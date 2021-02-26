package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func FormatCSV(w io.Writer, results []scanner.Result, _ string, options ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, result := range results {
		records = append(records, []string{
			result.Range.Filename,
			strconv.Itoa(result.Range.StartLine),
			strconv.Itoa(result.Range.EndLine),
			string(result.RuleID),
			string(result.Severity),
			result.Description,
			result.Link,
			strconv.FormatBool(result.Passed),
		})
	}

	csvWriter := csv.NewWriter(w)

	for _, record := range records {
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("error writing record to csv: %s", err)
		}
	}

	csvWriter.Flush()

	return csvWriter.Error()
}

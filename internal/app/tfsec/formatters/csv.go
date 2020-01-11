package formatters

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

func FormatCSV(results []scanner.Result) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link"},
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
		})
	}

	w := csv.NewWriter(os.Stdout)

	for _, record := range records {
		if err := w.Write(record); err != nil {
			return fmt.Errorf("error writing record to csv: %s", err)
		}
	}

	w.Flush()

	return w.Error()
}

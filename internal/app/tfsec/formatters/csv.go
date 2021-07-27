package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/tfsec/pkg/result"
)

func FormatCSV(w io.Writer, results []result.Result, _ string, _ ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, res := range results {
		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}
		records = append(records, []string{
			res.Range().Filename,
			strconv.Itoa(res.Range().StartLine),
			strconv.Itoa(res.Range().EndLine),
			res.RuleID,
			string(res.Severity),
			res.Description,
			link,
			strconv.FormatBool(res.Status == result.Passed),
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

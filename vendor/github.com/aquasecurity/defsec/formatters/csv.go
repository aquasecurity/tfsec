package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/defsec/rules"
)

func FormatCSV(w io.Writer, results []rules.Result, _ string, _ ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, res := range results {
		var link string
		if len(res.Rule().Links) > 0 {
			link = res.Rule().Links[0]
		}

		rng := res.CodeBlockMetadata().Range()
		if res.IssueBlockMetadata() != nil {
			rng = res.IssueBlockMetadata().Range()
		}

		records = append(records, []string{
			rng.GetFilename(),
			strconv.Itoa(rng.GetStartLine()),
			strconv.Itoa(rng.GetEndLine()),
			res.Rule().LongID(),
			string(res.Severity()),
			res.Description(),
			link,
			strconv.FormatBool(res.Status() == rules.StatusPassed),
		})
	}

	csvWriter := csv.NewWriter(w)

	for _, record := range records {
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("error writing record to csv: `%w`", err)
		}
	}

	csvWriter.Flush()

	return csvWriter.Error()
}

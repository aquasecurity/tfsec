package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/defsec/rules"
)

func FormatCSV(w io.Writer, results rules.Results, _ string, _ ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, res := range results {
		var link string
		if len(res.Rule().Links) > 0 {
			link = res.Rule().Links[0]
		}
		records = append(records, []string{
			res.Metadata().Range().GetFilename(),
			strconv.Itoa(res.Metadata().Range().GetStartLine()),
			strconv.Itoa(res.Metadata().Range().GetEndLine()),
			res.Rule().LongID(),
			string(res.Rule().Severity),
			res.Description(),
			link,
			strconv.FormatBool(res.Status() == rules.StatusPassed), // TODO
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

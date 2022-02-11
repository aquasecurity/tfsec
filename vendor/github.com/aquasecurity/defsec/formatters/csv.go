package formatters

import (
    "encoding/csv"
    "fmt"
    "strconv"

    "github.com/aquasecurity/defsec/rules"
)

func outputCSV(b ConfigurableFormatter, results []rules.Result) error {

    records := [][]string{
        {"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
    }

    for _, res := range results {
        var link string
        links := b.GetLinks(res)
        if len(links) > 0 {
            link = links[0]
        }

        rng := res.Range()

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

    csvWriter := csv.NewWriter(b.Writer())

    for _, record := range records {
        if err := csvWriter.Write(record); err != nil {
            return fmt.Errorf("error writing record to csv: `%w`", err)
        }
    }

    csvWriter.Flush()

    return csvWriter.Error()
}

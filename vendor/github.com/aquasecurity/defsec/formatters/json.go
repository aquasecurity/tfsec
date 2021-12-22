package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/rules"
)

type JSONOutput struct {
	Results []rules.FlatResult `json:"results"`
}

func FormatJSON(w io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")
	var flatResults []rules.FlatResult
	for _, result := range results {
		flatResults = append(flatResults, result.Flatten())
	}
	return jsonWriter.Encode(JSONOutput{flatResults})
}

package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/rules"
)

type JSONOutput struct {
	Results []rules.FlatResult `json:"results"`
}

func FormatJSON(w io.Writer, results rules.Results, _ string, options ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")
	return jsonWriter.Encode(JSONOutput{results.Flatten()})
}

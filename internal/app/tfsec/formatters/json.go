package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/rules"
)

type JSONOutput struct {
	Results rules.Results `json:"results"`
}

// TODO: add json annotations to defsec structs
func FormatJSON(w io.Writer, results rules.Results, _ string, options ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}

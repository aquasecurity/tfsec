package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/types"
)

type JSONOutput struct {
	Results []*result.Result `json:"results"`
}

func FormatJSON(w io.Writer, results []types.Result, _ string, options ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}

package formatters

import (
	"encoding/json"
	"io"

	"github.com/tfsec/tfsec/pkg/result"
)

type JSONOutput struct {
	Results []result.Result `json:"results"`
}

func FormatJSON(w io.Writer, results []result.Result, _ string, options ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}

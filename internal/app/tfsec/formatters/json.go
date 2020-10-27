package formatters

import (
	"encoding/json"
	"io"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type JSONOutput struct {
	Results []scanner.Result `json:"results"`
}

func FormatJSON(w io.Writer, results []scanner.Result, _ string) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}

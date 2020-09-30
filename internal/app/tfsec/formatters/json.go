package formatters

import (
	"encoding/json"
	"io"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

type JSONOutput struct {
	Results []scanner.Result `json:"results"`
}

func FormatJSON(w io.Writer, results []scanner.Result) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}

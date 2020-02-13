package formatters

import (
	"encoding/json"
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

type JSONOutput struct {
	Results []scanner.Result `json:"results"`
}

func FormatJSON(results []scanner.Result) error {

	data, err := json.MarshalIndent(JSONOutput{results}, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println(string(data))
	return nil
}

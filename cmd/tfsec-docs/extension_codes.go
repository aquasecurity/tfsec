package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type checkBlock struct {
	Code        string `json:"code"`
	LegacyCode  string `json:"legacy_code"`
	Service     string `json:"service"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Resolution  string `json:"resolution"`
	DocUrl      string `json:"doc_url"`
}

type checksBlock struct {
	Checks []checkBlock `json:"checks"`
}

func generateExtensionCodeFile(registeredChecks []*FileContent) error {
	var blocks []checkBlock

	for _, c := range registeredChecks {
		for _, check := range c.Checks {
			blocks = append(blocks, checkBlock{
				Code:        check.ID(),
				LegacyCode:  check.LegacyID,
				Service:     check.Service,
				Provider:    string(check.Provider),
				Description: check.Documentation.Summary,
				Impact:      check.Documentation.Impact,
				Resolution:  check.Documentation.Resolution,
				DocUrl:      fmt.Sprintf("https://tfsec.dev/docs/%s/%s/%s/", check.Provider, check.Service, check.ShortCode),
			})

		}
	}

	file, err := os.Create("checkdocs/codes.json")
	if err != nil {
		panic(err)
	}

	out, err := json.MarshalIndent(checksBlock{
		Checks: blocks,
	}, "", " ")
	if err != nil {
		panic(err)
	}

	_, err = file.Write(out)

	return err
}

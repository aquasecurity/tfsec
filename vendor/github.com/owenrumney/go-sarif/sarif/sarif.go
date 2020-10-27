package sarif

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/models"
)

type Version string

const Version210 Version = "2.1.0"

var versions = map[Version]string{
	Version210: "http://json.schemastore.org/sarif-2.1.0-rtm.4",
}

type Report struct {
	Version string        `json:"version"`
	Schema  string        `json:"$schema"`
	Runs    []*models.Run `json:"runs"`
}

func New(version Version) (*Report, error) {
	schema, err := getVersionSchema(version)
	if err != nil {
		return nil, err
	}
	return &Report{
		Version: string(version),
		Schema:  schema,
		Runs:    []*models.Run{},
	}, nil
}

func (sarif *Report) AddRun(toolName, informationUri string) *models.Run {
	run := models.NewRun(toolName, informationUri)
	sarif.Runs = append(sarif.Runs, run)
	return run
}

func getVersionSchema(version Version) (string, error) {
	for ver, schema := range versions {
		if ver == version {
			return schema, nil
		}
	}
	return "", errors.New(fmt.Sprintf("version [%s] is not supported", version))
}

func (sarif *Report) Write(w io.Writer) error {
	marshal, err := json.Marshal(sarif)
	if err != nil {
		return err
	}
	_, err = w.Write(marshal)
	return err
}

func (sarif *Report) PrettyWrite(w io.Writer) error {
	marshal, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(marshal)
	return err
}

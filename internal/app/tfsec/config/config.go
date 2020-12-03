package config

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	SeverityOverrides map[string]string `json:"severity_overrides,omitempty" yaml:"severity_overrides,omitempty"`
	ExcludedChecks    []string          `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

func LoadConfig(configFilePath string) (*Config, error) {
	var config = &Config{}

	if _, err := os.Stat(configFilePath); err != nil {
		return nil, err
	}

	configFileContent, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	ext := filepath.Ext(configFilePath)
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(configFileContent, config)
		if err != nil {
			return nil, err
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(configFileContent, config)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("couldn't process the file %s", configFilePath)
	}

	return config, nil
}

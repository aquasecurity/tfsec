package config

import (
	"encoding/json"
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	SeverityOverrides map[string]string `json:"severity_overrides,omitempty" yaml:"severity_overrides,omitempty"`
}

func LoadConfig(configFilePath string) (*Config, error) {
	var config = &Config{}

	if _, err := os.Stat(configFilePath); err != nil {
		if os.IsNotExist(err) {
			debug.Log("Failed to load the config file, not found. %s", configFilePath)
			return config, nil
		} else {
		    return nil, err
		}
	}

	configFileContent, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return config, err
	}

	ext := filepath.Ext(configFilePath)
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(configFileContent, &config)
		if err != nil {
			return config, err
		}
	case ".yml":
	case ".yaml":
		err = yaml.Unmarshal(configFileContent, &config)
		if err != nil {
			return config, nil
		}
	default:
		return config, fmt.Errorf("couldn't process the file %s", configFilePath)
	}

	return config, nil
}

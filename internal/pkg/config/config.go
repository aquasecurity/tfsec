package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/severity"
	"gopkg.in/yaml.v2"
)

type Config struct {
	MinimumSeverity        string            `json:"minimum_severity,omitempty" yaml:"minimum_severity,omitempty"`
	SeverityOverrides      map[string]string `json:"severity_overrides,omitempty" yaml:"severity_overrides,omitempty"`
	ExcludedChecks         []string          `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	IncludedChecks         []string          `json:"include,omitempty" yaml:"include,omitempty"`
	ExcludeIgnores         []string          `json:"exclude_ignores,omitempty" yaml:"exclude_ignores,omitempty"`
	MinimumRequiredVersion string            `json:"min_required_version" yaml:"min_required_version,omitempty"`
}

func LoadConfig(configFilePath string) (*Config, error) {
	var config = &Config{}

	if _, err := os.Stat(configFilePath); err != nil {
		return nil, fmt.Errorf("failed to access config file '%s': %w", configFilePath, err)
	}

	configFileContent, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", configFilePath, err)
	}

	ext := filepath.Ext(configFilePath)
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(configFileContent, config)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file '%s': %w", configFilePath, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(configFileContent, config)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file '%s': %w", configFilePath, err)
		}
	default:
		return nil, fmt.Errorf("couldn't process the file %s", configFilePath)
	}

	rewriteSeverityOverrides(config)

	return config, nil
}

func (c *Config) GetValidExcludedChecks() (excludedChecks []string) {
	for _, check := range c.ExcludedChecks {
		if strings.Contains(check, ":") {
			parts := strings.Split(check, ":")
			if len(parts) == 2 {
				if expiry, err := time.Parse("2006-01-02", parts[1]); err == nil {
					if expiry.Before(time.Now()) {
						continue
					}
				}
			}
			excludedChecks = append(excludedChecks, parts[0])
		} else {
			excludedChecks = append(excludedChecks, check)
		}
	}
	return excludedChecks
}

func rewriteSeverityOverrides(config *Config) {
	for k, s := range config.SeverityOverrides {
		config.SeverityOverrides[k] = string(severity.StringToSeverity(s))
	}
}

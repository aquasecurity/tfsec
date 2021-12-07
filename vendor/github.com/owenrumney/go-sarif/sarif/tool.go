package sarif

type Tool struct {
	PropertyBag
	Driver *Driver `json:"driver"`
}

type Driver struct {
	PropertyBag
	Name           string  `json:"name"`
	Version        *string `json:"version,omitempty"`
	InformationURI *string `json:"informationUri"`
	Rules          []*Rule `json:"rules,omitempty"`
}

// WithVersion specifies tool version, in whatever format it natively provides. Returns updated driver.
func (driver *Driver) WithVersion(version string) *Driver {
	driver.Version = &version
	return driver
}

func (driver *Driver) getOrCreateRule(rule *Rule) uint {
	for i, r := range driver.Rules {
		if r.ID == rule.ID {
			return uint(i)
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return uint(len(driver.Rules) - 1)
}

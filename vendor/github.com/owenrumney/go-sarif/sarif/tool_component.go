package sarif

type ToolComponent struct {
	PropertyBag
	Name           string                 `json:"name"`
	Version        *string                `json:"version,omitempty"`
	InformationURI *string                `json:"informationUri"`
	Notifications  []*ReportingDescriptor `json:"notifications,omitempty"`
	Rules          []*ReportingDescriptor `json:"rules,omitempty"`
	Taxa           []*ReportingDescriptor `json:"taxa,omitempty"`
}

// WithVersion specifies tool version, in whatever format it natively provides. Returns updated driver.
func (driver *ToolComponent) WithVersion(version string) *ToolComponent {
	driver.Version = &version
	return driver
}

func (driver *ToolComponent) getOrCreateRule(rule *ReportingDescriptor) uint {
	for i, r := range driver.Rules {
		if r.ID == rule.ID {
			return uint(i)
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return uint(len(driver.Rules) - 1)
}

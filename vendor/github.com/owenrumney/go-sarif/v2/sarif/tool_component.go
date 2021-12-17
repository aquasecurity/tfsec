package sarif

// ToolComponent ...
type ToolComponent struct {
	Name           string                 `json:"name"`
	Version        *string                `json:"version,omitempty"`
	InformationURI *string                `json:"informationUri"`
	Notifications  []*ReportingDescriptor `json:"notifications,omitempty"`
	Rules          []*ReportingDescriptor `json:"rules,omitempty"`
	Taxa           []*ReportingDescriptor `json:"taxa,omitempty"`
	PropertyBag
}

// NewDriver creates a new Driver and returns a pointer to it
func NewDriver(name string) *ToolComponent {
	return &ToolComponent{
		Name: name,
	}
}

// NewVersionedDriver creates a new VersionedDriver and returns a pointer to it
func NewVersionedDriver(name, version string) *ToolComponent {
	return &ToolComponent{
		Name:    name,
		Version: &version,
	}
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

// WithInformationURI sets the InformationURI
func (driver *ToolComponent) WithInformationURI(informationURI string) *ToolComponent {
	driver.InformationURI = &informationURI
	return driver
}

// WithNotifications sets the Notifications
func (driver *ToolComponent) WithNotifications(notifications []*ReportingDescriptor) *ToolComponent {
	driver.Notifications = notifications
	return driver
}

// AddNotification ...
func (driver *ToolComponent) AddNotification(notification *ReportingDescriptor) {
	driver.Notifications = append(driver.Notifications, notification)
}

// WithRules sets the Rules
func (driver *ToolComponent) WithRules(rules []*ReportingDescriptor) *ToolComponent {
	for _, rule := range rules {
		driver.getOrCreateRule(rule)
	}
	return driver
}

// AddRule ...
func (driver *ToolComponent) AddRule(rule *ReportingDescriptor) {
	driver.getOrCreateRule(rule)

}

// WithTaxa sets the Taxa
func (driver *ToolComponent) WithTaxa(taxa []*ReportingDescriptor) *ToolComponent {
	driver.Taxa = taxa
	return driver
}

// AddTaxa ...
func (driver *ToolComponent) AddTaxa(taxa *ReportingDescriptor) {
	driver.Taxa = append(driver.Taxa, taxa)
}

func (driver *ToolComponent) getRuleIndex(id *string) int{
	for i, rule := range driver.Rules {
		if rule.ID == *id {
			return i
		}
	}
	return -1
}

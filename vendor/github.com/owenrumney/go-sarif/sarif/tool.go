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

// Rule specifies a Sarif Rule object
type Rule struct {
	PropertyBag
	ID               string                    `json:"id"`
	Name             *string                   `json:"name,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	HelpURI          *string                   `json:"helpUri,omitempty"`
	Help             *MultiformatMessageString `json:"help,omitempty"`
	Properties       map[string]string         `json:"properties,omitempty"`
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

func newRule(ruleID string) *Rule {
	return &Rule{
		ID: ruleID,
	}
}

// WithName specifies rule name that is understandable to an end user and returns the updated rule.
func (rule *Rule) WithName(name string) *Rule {
	rule.Name = &name
	return rule
}

// WithDescription specifies short description for a rule and returns the updated rule.
// Short description should be a single sentence that is understandable when visible space is limited to a single line
// of text.
func (rule *Rule) WithDescription(description string) *Rule {
	rule.ShortDescription = NewMultiformatMessageString(description)
	return rule
}

// WithFullDescription specifies full description for a rule and returns the updated rule.
// Full description should, as far as possible, provide details sufficient to enable resolution of any problem indicated
// by the result.
func (rule *Rule) WithFullDescription(description *MultiformatMessageString) *Rule {
	rule.FullDescription = description
	return rule
}

// WithHelpURI specifies a helpURI for a rule and returns the updated rule
func (rule *Rule) WithHelpURI(helpURI string) *Rule {
	rule.HelpURI = &helpURI
	return rule
}

// WithHelp specifies a help text  for a rule and returns the updated rule
func (rule *Rule) WithHelp(helpText string) *Rule {
	rule.Help = NewMultiformatMessageString(helpText)
	return rule
}

// WithProperties specifies properties for a rule and returns the updated rule
func (rule *Rule) WithProperties(properties map[string]string) *Rule {
	rule.Properties = properties
	return rule
}

package models

type tool struct {
	Driver *driver `json:"driver"`
}

type driver struct {
	Name           string  `json:"name"`
	InformationURI string  `json:"informationUri"`
	Rules          []*Rule `json:"rules,omitempty"`
}

// Rule specifies a Sarif Rule object
type Rule struct {
	ID               string            `json:"id"`
	ShortDescription *textBlock        `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Help             *textBlock        `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

func (driver *driver) getOrCreateRule(rule *Rule) int {
	for i, r := range driver.Rules {
		if r.ID == rule.ID {
			return i
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return len(driver.Rules) - 1
}

func newRule(ruleID string) *Rule {
	return &Rule{
		ID: ruleID,
	}
}

// WithDescription specifies a description for a rule and returns the updated rule
func (rule *Rule) WithDescription(description string) *Rule {
	rule.ShortDescription = &textBlock{
		Text: description,
	}
	return rule
}

// WithHelpURI specifies a helpURI for a rule and returns the updated rule
func (rule *Rule) WithHelpURI(helpURI string) *Rule {
	rule.HelpURI = helpURI
	return rule
}

// WithHelp specifies a help text  for a rule and returns the updated rule
func (rule *Rule) WithHelp(helpText string) *Rule {
	rule.Help = &textBlock{
		Text: helpText,
	}
	return rule
}

// WithProperties specifies properties for a rule and returns the updated rule
func (rule *Rule) WithProperties(properties map[string]string) *Rule {
	rule.Properties = properties
	return rule
}

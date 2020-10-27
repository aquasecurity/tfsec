package models

type Tool struct {
	Driver *Driver `json:"driver"`
}

type Driver struct {
	Name           string  `json:"name"`
	InformationUri string  `json:"informationUri"`
	Rules          []*Rule `json:"rules,omitempty"`
}

type Rule struct {
	Id               string            `json:"id"`
	ShortDescription *TextBlock        `json:"shortDescription"`
	HelpUri          string            `json:"helpUri"`
	Properties       map[string]string `json:"properties,omitempty"`
}

func (driver *Driver) getOrCreateRule(rule *Rule) int {
	for i, r := range driver.Rules {
		if r.Id == rule.Id {
			return i
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return len(driver.Rules) - 1
}

func newRule(ruleId string) *Rule {
	return &Rule{
		Id: ruleId,
	}
}

func (rule *Rule) WithDescription(description string) *Rule {
	rule.ShortDescription = &TextBlock{
		Text: description,
	}
	return rule
}

func (rule *Rule) WithHelpUri(helpUrl string) *Rule {
	rule.HelpUri = helpUrl
	return rule
}

func (rule *Rule) WithProperties(properties map[string]string) *Rule {
	rule.Properties = properties
	return rule
}

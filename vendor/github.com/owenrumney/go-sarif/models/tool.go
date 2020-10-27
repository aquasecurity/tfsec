package models

type tool struct {
	Driver *driver `json:"driver"`
}

type driver struct {
	Name           string  `json:"name"`
	InformationUri string  `json:"informationUri"`
	Rules          []*rule `json:"rules,omitempty"`
}

type rule struct {
	Id               string            `json:"id"`
	ShortDescription *textBlock        `json:"shortDescription"`
	HelpUri          string            `json:"helpUri,omitempty"`
	Help             *textBlock        `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

func (driver *driver) getOrCreateRule(rule *rule) int {
	for i, r := range driver.Rules {
		if r.Id == rule.Id {
			return i
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return len(driver.Rules) - 1
}

func newRule(ruleId string) *rule {
	return &rule{
		Id: ruleId,
	}
}

func (rule *rule) WithDescription(description string) *rule {
	rule.ShortDescription = &textBlock{
		Text: description,
	}
	return rule
}

func (rule *rule) WithHelpUri(helpUrl string) *rule {
	rule.HelpUri = helpUrl
	return rule
}

func (rule *rule) WithHelp(helpText string) *rule {
	rule.Help = &textBlock{
		Text: helpText,
	}
	return rule
}

func (rule *rule) WithProperties(properties map[string]string) *rule {
	rule.Properties = properties
	return rule
}

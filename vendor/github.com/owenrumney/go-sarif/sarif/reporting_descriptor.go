package sarif

type ReportingConfiguration struct {
	Enabled    bool         `json:"enabled,omitempty"`
	Level      interface{}  `json:"level,omitempty"`
	Parameters *PropertyBag `json:"parameters,omitempty"`
	Properties *PropertyBag `json:"properties,omitempty"`
	Rank       float64      `json:"rank,omitempty"`
}

// ReportingDescriptor specifies a Sarif ReportingDescriptor object
type ReportingDescriptor struct {
	PropertyBag
	ID                   string                    `json:"id"`
	Name                 *string                   `json:"name,omitempty"`
	ShortDescription     *MultiformatMessageString `json:"shortDescription"`
	FullDescription      *MultiformatMessageString `json:"fullDescription,omitempty"`
	DefaultConfiguration *ReportingConfiguration   `json:"defaultConfiguration,omitempty"`
	HelpURI              *string                   `json:"helpUri,omitempty"`
	Help                 *MultiformatMessageString `json:"help,omitempty"`
	Properties           Properties                `json:"properties,omitempty"`
}

func newRule(ruleID string) *ReportingDescriptor {
	return &ReportingDescriptor{
		ID: ruleID,
	}
}

// WithName specifies rule name that is understandable to an end user and returns the updated rule.
func (rule *ReportingDescriptor) WithName(name string) *ReportingDescriptor {
	rule.Name = &name
	return rule
}

// WithDescription specifies short description for a rule and returns the updated rule.
// Short description should be a single sentence that is understandable when visible space is limited to a single line
// of text.
func (rule *ReportingDescriptor) WithDescription(description string) *ReportingDescriptor {
	rule.ShortDescription = NewMultiformatMessageString(description)
	return rule
}

// WithShortDescription specifies short description for a rule and returns the updated rule.
// Short description should be a single sentence that is understandable when visible space is limited to a single line
// of text.
func (rule *ReportingDescriptor) WithShortDescription(description *MultiformatMessageString) *ReportingDescriptor {
	rule.ShortDescription = description
	return rule
}

// WithFullDescription specifies full description for a rule and returns the updated rule.
// Full description should, as far as possible, provide details sufficient to enable resolution of any problem indicated
// by the result.
func (rule *ReportingDescriptor) WithFullDescription(description *MultiformatMessageString) *ReportingDescriptor {
	rule.FullDescription = description
	return rule
}

// WithHelpURI specifies a helpURI for a rule and returns the updated rule
func (rule *ReportingDescriptor) WithHelpURI(helpURI string) *ReportingDescriptor {
	rule.HelpURI = &helpURI
	return rule
}

// WithHelp specifies a help text  for a rule and returns the updated rule
func (rule *ReportingDescriptor) WithHelp(helpText string) *ReportingDescriptor {
	rule.Help = NewMultiformatMessageString(helpText)
	return rule
}

// WithMarkdownHelp specifies a help text  for a rule and returns the updated rule
func (rule *ReportingDescriptor) WithMarkdownHelp(markdownText string) *ReportingDescriptor {
	rule.Help = NewMarkdownMultiformatMessageString(markdownText)
	return rule
}

// WithProperties specifies properties for a rule and returns the updated rule
func (rule *ReportingDescriptor) WithProperties(properties Properties) *ReportingDescriptor {
	rule.Properties = properties
	return rule
}

// AttachPropertyBag adds a property bag to a rule
func (rule *ReportingDescriptor) AttachPropertyBag(pb *PropertyBag) {
	rule.Properties = pb.Properties
}

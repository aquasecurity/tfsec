package sarif

type MultiformatMessageString struct {
	PropertyBag
	Text     string  `json:"text"`
	Markdown *string `json:"markdown,omitempty"`
}

func NewMultiformatMessageString(text string) *MultiformatMessageString {
	return &MultiformatMessageString{
		Text: text,
	}
}

func (m *MultiformatMessageString) WithMarkdown(markdown string) *MultiformatMessageString {
	m.Markdown = &markdown
	return m
}

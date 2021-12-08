package sarif

type MultiformatMessageString struct {
	PropertyBag
	Text     *string `json:"text,omitempty"`
	Markdown *string `json:"markdown,omitempty"`
}

func NewMarkdownMultiformatMessageString(markdown string) *MultiformatMessageString {
	return &MultiformatMessageString{
		Markdown: &markdown,
	}
}

func NewMultiformatMessageString(text string) *MultiformatMessageString {
	return &MultiformatMessageString{
		Text: &text,
	}
}

func (m *MultiformatMessageString) WithMarkdown(markdown string) *MultiformatMessageString {
	m.Markdown = &markdown
	return m
}

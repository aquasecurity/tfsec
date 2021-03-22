package models

type MessageBuilder struct {
	message *Message
}

func (m *MessageBuilder) WithText(text string) *MessageBuilder {
	m.message.Text = &text
	return m
}

func (m *MessageBuilder) WithMarkdown(markdown string) *MessageBuilder {
	m.message.Markdown = &markdown
	return m
}

func (m *MessageBuilder) WithId(id string) *MessageBuilder {
	m.message.Id = &id
	return m
}

func (m *MessageBuilder) WithArguments(args []string) *MessageBuilder {
	m.message.Arguments = args
	return m
}

func (m *MessageBuilder) Get() *Message {
	return m.message
}

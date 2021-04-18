package sarif

// TextBlock is a general block which includes a text attribute
type TextBlock struct {
	Text string `json:"text"`
}

func NewTextBlock(text string) *TextBlock {
	return &TextBlock{
		Text: text,
	}
}

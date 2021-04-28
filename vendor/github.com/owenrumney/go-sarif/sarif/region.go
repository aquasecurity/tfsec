package sarif

type Region struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541123
	PropertyBag
	StartLine      *int             `json:"startLine,omitempty"`
	StartColumn    *int             `json:"startColumn,omitempty"`
	EndLine        *int             `json:"endLine,omitempty"`
	EndColumn      *int             `json:"endColumn,omitempty"`
	CharOffset     *int             `json:"charOffset,omitempty"`
	CharLength     *int             `json:"charLength,omitempty"`
	ByteOffset     *int             `json:"byteOffset,omitempty"`
	ByteLength     *int             `json:"byteLength,omitempty"`
	Snippet        *ArtifactContent `json:"snippet,omitempty"`
	Message        *Message         `json:"message,omitempty"`
	SourceLanguage *string          `json:"sourceLanguage,omitempty"`
}

func NewRegion() *Region {
	return &Region{}
}

func NewSimpleRegion(startLine, endLine int) *Region {
	return NewRegion().
		WithStartLine(startLine).
		WithEndLine(endLine)
}

func (r *Region) WithStartLine(startLine int) *Region {
	r.StartLine = &startLine
	return r
}

func (r *Region) WithStartColumn(startColumn int) *Region {
	r.StartColumn = &startColumn
	return r
}

func (r *Region) WithEndLine(endLine int) *Region {
	r.EndLine = &endLine
	return r
}

func (r *Region) WithEndColumn(endColumn int) *Region {
	r.EndColumn = &endColumn
	return r
}

func (r *Region) WithCharOffset(charOffset int) *Region {
	r.CharOffset = &charOffset
	return r
}

func (r *Region) WithCharLength(charLength int) *Region {
	r.CharLength = &charLength
	return r
}

func (r *Region) WithByteOffset(byteOffset int) *Region {
	r.ByteOffset = &byteOffset
	return r
}

func (r *Region) WithByteLength(byteLength int) *Region {
	r.ByteLength = &byteLength
	return r
}

func (r *Region) WithSnippet(snippet *ArtifactContent) *Region {
	r.Snippet = snippet
	return r
}

func (r *Region) WithMessage(message *Message) *Region {
	r.Message = message
	return r
}

func (r *Region) WithSourceLanguage(sourceLanguage string) *Region {

	return r
}

package models

type region struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541123
	StartLine      *int             `json:"startLine,omitempty"`
	StartColumn    *int             `json:"startColumn,omitempty"`
	EndLine        *int             `json:"endLine,omitempty"`
	EndColumn      *int             `json:"endColumn,omitempty"`
	CharOffset     *int             `json:"charOffset,omitempty"`
	CharLength     *int             `json:"charLength,omitempty"`
	ByteOffset     *int             `json:"byteOffset,omitempty"`
	ByteLength     *int             `json:"byteLength,omitempty"`
	Snippet        *artifactContent `json:"snippet,omitempty"`
	Message        *Message         `json:"message,omitempty"`
	SourceLanguage *string          `json:"sourceLanguage,omitempty"`
}

type RegionBuilder struct {
	region *region
}

func NewRegionBuilder() *RegionBuilder {
	return &RegionBuilder{
		region: &region{},
	}
}

func (rb *RegionBuilder) Get() *region {
	return rb.region
}

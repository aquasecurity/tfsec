package sarif

type Fix struct {
	PropertyBag
	Description     *Message          `json:"description,omitempty"`
	ArtifactChanges []*ArtifactChange `json:"artifactChanges"` //	required
}

func NewFix() *Fix {
	return &Fix{}
}

func (f *Fix) WithDescription(message *Message) *Fix {
	f.Description = message
	return f
}

func (f *Fix) WithArtifactChange(ac *ArtifactChange) *Fix {
	f.ArtifactChanges = append(f.ArtifactChanges, ac)
	return f
}

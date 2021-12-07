package sarif

type Replacement struct {
	PropertyBag
	DeletedRegion   Region           `json:"deletedRegion"`
	InsertedContent *ArtifactContent `json:"insertedContent,omitempty"`
}

func NewReplacement(region *Region) *Replacement {
	return &Replacement{
		DeletedRegion: *region,
	}
}

func (r *Replacement) WithInsertedContent(artifactContent *ArtifactContent) *Replacement {
	r.InsertedContent = artifactContent
	return r
}

package sarif

type ArtifactChange struct {
	PropertyBag
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []*Replacement   `json:"replacements"` //required
}

func NewArtifactChange(artifactLocation *ArtifactLocation) *ArtifactChange {
	return &ArtifactChange{
		ArtifactLocation: *artifactLocation,
	}
}

func (a *ArtifactChange) WithReplacement(replacement *Replacement) *ArtifactChange {
	a.Replacements = append(a.Replacements, replacement)
	return a
}

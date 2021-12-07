package sarif

type PhysicalLocation struct {
	PropertyBag
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
	Address          *Address          `json:"address,omitempty"`
}

func NewPhysicalLocation() *PhysicalLocation {
	return &PhysicalLocation{}
}

func (pl *PhysicalLocation) WithArtifactLocation(artifactLocation *ArtifactLocation) *PhysicalLocation {
	pl.ArtifactLocation = artifactLocation
	return pl
}

func (pl *PhysicalLocation) WithRegion(region *Region) *PhysicalLocation {
	pl.Region = region
	return pl
}
func (pl *PhysicalLocation) WithContextRegion(contextRegion *Region) *PhysicalLocation {
	pl.ContextRegion = contextRegion
	return pl
}

func (pl *PhysicalLocation) WithAddress(address *Address) *PhysicalLocation {
	pl.Address = address
	return pl
}

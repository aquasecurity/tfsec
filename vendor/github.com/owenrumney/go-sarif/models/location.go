package models

type location struct {
	Id               *uint                   `json:"id,omitempty"`
	PhysicalLocation *physicalLocation       `json:"physicalLocation,omitempty"`
	LogicalLocations []*logicalLocation      `json:"logicalLocations,omitempty"`
	Message          *Message                `json:"message,omitempty"`
	Annotations      []*region               `json:"annotations,omitempty"`
	Relationships    []*locationRelationship `json:"relationships,omitempty"`
}

type physicalLocation struct {
	ArtifactLocation *artifactLocation `json:"artifactLocation,omitempty"`
	Region           *region           `json:"region,omitempty"`
	ContextRegion    *region           `json:"contextRegion,omitempty"`
	Address          *address          `json:"address,omitempty"`
}

type logicalLocation struct {
	Index              *uint   `json:"index,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	DecoratedName      *string `json:"decoratedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
}

type locationRelationship struct {
	Target      uint     `json:"target"`
	Kinds       []string `json:"kinds,omitempty"`
	Description *Message `json:"description,omitempty"`
}


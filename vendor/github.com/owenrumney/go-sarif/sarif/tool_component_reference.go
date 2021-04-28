package sarif

type ToolComponentReference struct {
	PropertyBag
	Name  *string `json:"name"`
	Index *uint   `json:"index"`
	Guid  *string `json:"guid"`
}

func NewToolComponentReference() *ToolComponentReference {
	return &ToolComponentReference{}
}

func (t *ToolComponentReference) WithName(name string) *ToolComponentReference {
	t.Name = &name
	return t
}

func (t *ToolComponentReference) WithIndex(index int) *ToolComponentReference {
	i := uint(index)
	t.Index = &i
	return t
}

func (t *ToolComponentReference) WithGuid(guid string) *ToolComponentReference {
	t.Guid = &guid
	return t
}

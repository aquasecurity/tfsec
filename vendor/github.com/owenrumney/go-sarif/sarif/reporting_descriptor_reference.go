package sarif

type ReportingDescriptorReference struct {
	PropertyBag
	Id            *string                 `json:"id,omitempty"`
	Index         *uint                   `json:"index,omitempty"`
	Guid          *string                 `json:"guid,omitempty"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

func NewReportingDescriptorReference() *ReportingDescriptorReference {
	return &ReportingDescriptorReference{}
}

func (r *ReportingDescriptorReference) WithId(id string) *ReportingDescriptorReference {
	r.Id = &id
	return r
}

func (r *ReportingDescriptorReference) WithIndex(index int) *ReportingDescriptorReference {
	i := uint(index)
	r.Index = &i
	return r
}

func (r *ReportingDescriptorReference) WithGuid(guid string) *ReportingDescriptorReference {
	r.Guid = &guid
	return r
}

func (r *ReportingDescriptorReference) WithToolComponentReference(toolComponentRef *ToolComponentReference) *ReportingDescriptorReference {
	r.ToolComponent = toolComponentRef
	return r
}

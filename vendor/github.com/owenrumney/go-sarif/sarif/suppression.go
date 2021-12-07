package sarif

type Suppression struct {
	PropertyBag
	Kind          string    `json:"kind"`
	Status        *string   `json:"status"`
	Location      *Location `json:"location"`
	Guid          *string   `json:"guid"`
	Justification *string   `json:"justification"`
}

func NewSuppression(kind string) *Suppression {
	return &Suppression{
		Kind: kind,
	}
}

func (s *Suppression) WithStatus(status string) *Suppression {
	s.Status = &status
	return s
}

func (s *Suppression) WithLocation(location *Location) *Suppression {
	s.Location = location
	return s
}

func (s *Suppression) WithGuid(guid string) *Suppression {
	s.Guid = &guid
	return s
}

func (s *Suppression) WithJustifcation(justification string) *Suppression {
	s.Justification = &justification
	return s
}

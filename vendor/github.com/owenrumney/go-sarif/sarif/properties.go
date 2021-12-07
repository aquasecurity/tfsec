package sarif

type Properties map[string]interface{}

type PropertyBag struct {
	Properties Properties `json:"properties,omitempty"`
}

func NewPropertyBag() *PropertyBag {
	return &PropertyBag{
		Properties: Properties{},
	}
}

func (pb *PropertyBag) Add(key string, value interface{}) {
	pb.Properties[key] = value
}

func (pb *PropertyBag) AddString(key, value string) {
	pb.Add(key, value)
}

func (pb *PropertyBag) AddBoolean(key string, value bool) {
	pb.Add(key, value)
}

func (pb *PropertyBag) AddInteger(key string, value int) {
	pb.Add(key, value)
}

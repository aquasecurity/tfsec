package sarif

type Tool struct {
	PropertyBag
	Driver *ToolComponent `json:"driver"`
}


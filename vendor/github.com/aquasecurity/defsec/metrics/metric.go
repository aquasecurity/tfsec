package metrics

type Metric interface {
	Name() string
	Value() string
}

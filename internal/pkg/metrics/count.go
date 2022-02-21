package metrics

import (
	"fmt"
	"sync"
)

type CounterMetric interface {
	Metric
	Increment(delta int)
}

type counter struct {
	sync.Mutex
	name  string
	count uint64
}

// Counter creates a new counter metric (or returns an existing one if one already exists with this name and category)
func Counter(category, name string) CounterMetric {
	return newCounter(category, name, false)
}

// DebugCounter creates a new debug counter metric (or returns an existing one if one already exists with this name and category)
func DebugCounter(category, name string) CounterMetric {
	return newCounter(category, name, true)
}

func newCounter(category string, name string, debug bool) CounterMetric {
	if metric := useCategory(category, debug).findMetric(name); metric != nil {
		if c, ok := metric.(CounterMetric); ok {
			return c
		}
	}
	count := &counter{
		name: name,
	}
	useCategory(category, debug).setMetric(count)
	return count
}

func (c *counter) Name() string {
	return c.name
}

func (c *counter) Value() string {
	return fmt.Sprintf("%d", c.count)
}

func (c *counter) Increment(delta int) {
	c.Lock()
	defer c.Unlock()
	c.count += uint64(delta)
}

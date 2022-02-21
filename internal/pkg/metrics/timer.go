package metrics

import (
	"sync"
	"time"
)

type TimerMetric interface {
	Metric
	Start()
	Stop()
}

type timerMetric struct {
	sync.Mutex
	name    string
	started time.Time
	total   time.Duration
}

// Timer returns a new timer (or returns an existing one if one exists with this category and name)
func Timer(category, name string) TimerMetric {
	return newTimer(category, name, false)
}

// DebugTimer returns a new debug timer (or returns an existing one if one exists with this category and name)
func DebugTimer(category, name string) TimerMetric {
	return newTimer(category, name, true)
}

func newTimer(category string, name string, debug bool) TimerMetric {
	if metric := useCategory(category, debug).findMetric(name); metric != nil {
		if c, ok := metric.(TimerMetric); ok {
			return c
		}
	}
	timer := &timerMetric{
		name:    name,
		started: time.Now(),
	}
	useCategory(category, debug).setMetric(timer)
	return timer
}

func (t *timerMetric) Start() {
	now := time.Now()
	t.Lock()
	defer t.Unlock()
	t.started = now

}

func (t *timerMetric) Stop() {
	now := time.Now()
	t.Lock()
	defer t.Unlock()
	t.total += now.Sub(t.started)
}

func (t *timerMetric) Name() string {
	return t.name
}

func (t *timerMetric) Value() string {
	return t.total.String()
}

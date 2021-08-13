package metrics

import (
	"time"

	"github.com/aquasecurity/tfsec/pkg/severity"
)

var recordedTimes []*Timer

type Operation string

const (
	DiskIO     Operation = "disk i/o"
	HCLParse   Operation = "parsing HCL"
	Evaluation Operation = "evaluating values"
	Check      Operation = "running checks"
)

type Timer struct {
	started   time.Time
	operation Operation
	duration  time.Duration
}

func Start(op Operation) *Timer {
	return &Timer{
		started:   time.Now(),
		operation: op,
	}
}

func (t *Timer) Stop() {
	t.duration = time.Since(t.started)
	recordedTimes = append(recordedTimes, t)
}

type Count string

const (
	ModuleLoadCount Count = "modules"
	BlocksLoaded    Count = "blocks"
	FilesLoaded     Count = "files loaded"
	IgnoredChecks   Count = "ignored checks"
)

var counts = map[Count]int{}

func Add(c Count, delta int) {
	counts[c] += delta
}

func TimerSummary() map[Operation]time.Duration {

	times := make(map[Operation]time.Duration)
	for _, recorded := range recordedTimes {
		sum := times[recorded.operation]
		sum += recorded.duration
		times[recorded.operation] = sum
	}

	return times
}

func CountSummary() map[Count]int {
	return counts
}

var severities = map[severity.Severity]int{}

func AddResult(s severity.Severity) {
	severities[s]++
}

func CountSeverity(sev severity.Severity) int {
	val, ok := severities[sev]
	if !ok {
		return 0
	}
	return val
}

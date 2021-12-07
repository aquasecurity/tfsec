package sarif

import "time"

// Invocation describes the runtime environment of the analysis tool run.
type Invocation struct {
	PropertyBag
	StartTimeUTC        *time.Time        `json:"startTimeUtc,omitempty"`
	EndTimeUTC          *time.Time        `json:"endTimeUtc,omitempty"`
	ExecutionSuccessful bool              `json:"executionSuccessful"`
	WorkingDirectory    *ArtifactLocation `json:"workingDirectory,omitempty"`
}

// WithStartTimeUTC sets the instant when the invocation started and returns the same Invocation.
func (i *Invocation) WithStartTimeUTC(startTime time.Time) *Invocation {
	startTimeUTC := startTime.UTC()
	i.StartTimeUTC = &startTimeUTC
	return i
}

// WithEndTimeUTC sets the instant when the invocation ended and returns the same Invocation.
func (i *Invocation) WithEndTimeUTC(endTime time.Time) *Invocation {
	endTimeUTC := endTime.UTC()
	i.EndTimeUTC = &endTimeUTC
	return i
}

// WithWorkingDirectory sets the current working directory of the invocation and returns the same Invocation.
func (i *Invocation) WithWorkingDirectory(workingDirectory *ArtifactLocation) *Invocation {
	i.WorkingDirectory = workingDirectory
	return i
}

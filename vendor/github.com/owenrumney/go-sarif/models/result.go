package models

// Result represents the results block in the sarif report
type Result struct {
	Guid            *string                         `json:"guid,omitempty"`
	CorrelationGuid *string                         `json:"correlationGuid,omitempty"`
	RuleID          *string                         `json:"ruleId,omitempty"`
	RuleIndex       *uint                           `json:"ruleIndex,omitempty"`
	Rule            *reportingDescriptorReference   `json:"rule,omitempty"`
	Taxa            []*reportingDescriptorReference `json:"taxa,omitempty"`
	Kind            *string                         `json:"kind,omitempty"`
	Level           *string                         `json:"level,omitempty"`
	Message         Message                         `json:"message"`
	Locations       []*location                     `json:"locations,omitempty"`
	AnalysisTarget  *artifactLocation               `json:"analysisTarget,omitempty"`
	// WebRequest			*webRequest						`json:"webRequest,omitempty"`
	// WebResponse			*webResponse					`json:"webResponse,omitempty"`
	Fingerprints        map[string]interface{} `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]interface{} `json:"partialFingerprints,omitempty"`
	// CodeFlows			[]*codeFlows					`json:"codeFlows,omitempty"`
	// Graphs				[]*graphs						`json:"graphs,omitempty"`
	// GraphTraversals		[]*graphTraversals				`json:"graphTraversals,omitempty"`
	// Stacks				[]*stack						`json:"stacks,omitempty"`
	RelatedLocations []*location    `json:"relatedLocations,omitempty"`
	Suppressions     []*suppression `json:"suppressions,omitempty"`
	BaselineState    *string        `json:"baselineState,omitempty"`
	Rank             *float32       `json:"rank,omitempty"`
	// Attachments			[]*attachment					`json:"attachments,omitempty"`
	WorkItemUris    []string `json:"workItemUris,omitempty"` // can be null
	HostedViewerUri *string  `json:"hostedViewerUri,omitempty"`
	// Provenance			*resultProvenance				`json:"provenance,omitempty"`
	Fixes           []*fix `json:"fixes,omitempty"`
	OccurrenceCount *uint  `json:"occurrenceCount,omitempty"`
}

type reportingDescriptorReference struct {
	Id            *string                 `json:"id,omitempty"`
	Index         *uint                   `json:"index,omitempty"`
	Guid          *string                 `json:"guid,omitempty"`
	ToolComponent *toolComponentReference `json:"toolComponent,omitempty"`
}

type toolComponentReference struct {
	Name  *string `json:"name"`
	Index *uint   `json:"index"`
	Guid  *string `json:"guid"`
}

type Message struct { // https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540897
	Text      *string  `json:"text,omitempty"`
	Markdown  *string  `json:"markdown,omitempty"`
	Id        *string  `json:"id,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
}







type multiformatMessageString struct {
	Text     string  `json:"text"`
	Markdown *string `json:"markdown,omitempty"`
}

type address struct {
	Index              *uint   `json:"index,omitempty"`
	AbsoluteAddress    *uint   `json:"absoluteAddress,omitempty"`
	RelativeAddress    *int    `json:"relativeAddress,omitempty"`
	OffsetFromParent   *int    `json:"offsetFromParent,omitempty"`
	Length             *int    `json:"length,omitempty"`
	Name               *string `json:"name,omitempty"`
	FullyQualifiedName *string `json:"fullyQualifiedName,omitempty"`
	Kind               *string `json:"kind,omitempty"`
	ParentIndex        *uint   `json:"parentIndex,omitempty"`
}



type suppression struct {
	Kind          string    `json:"kind"`
	Status        *string   `json:"status"`
	Location      *location `json:"location"`
	Guid          *string   `json:"guid"`
	Justification *string   `json:"justification"`
}

type fix struct {
	Description     *Message          `json:"description,omitempty"`
	ArtifactChanges []*artifactChange `json:"artifactChanges"` //	required
}

type artifactChange struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Replacements     []*replacement   `json:"replacements"` //required
}

type replacement struct {
	DeletedRegion   region           `json:"deletedRegion"`
	InsertedContent *artifactContent `json:"insertedContent,omitempty"`
}

func newRuleResult(ruleID string) *Result {
	return &Result{
		RuleID: &ruleID,
	}
}

// WithLevel specifies the level of the finding, error, warning for a result and returns the updated result
func (result *Result) WithLevel(level string) *Result {
	result.Level = &level
	return result
}

// WithMessage specifies the message for a result and returns the updated result
func (result *Result) WithMessage(message string) *Result {
	result.Message.Text = &message
	return result
}

func (result *Result) NewMessageBuilder() *MessageBuilder {
	return &MessageBuilder{
		message: &result.Message,
	}
}

// WithLocationDetails specifies the location details of the Result and returns the update result
func (result *Result) WithLocationDetails(path string, startLine, startColumn int) *Result {
	physicalLocation := &physicalLocation{
		ArtifactLocation: &artifactLocation{
			URI: &path,
		},
		Region: &region{
			StartLine:   &startLine,
			StartColumn: &startColumn,
		},
	}
	result.Locations = append(result.Locations, &location{
		PhysicalLocation: physicalLocation,
	})
	return result
}

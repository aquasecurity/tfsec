package sam

import "github.com/aquasecurity/trivy-config-parsers/types"

type SAM struct {
	types.Metadata
	APIs          []API
	Applications  []Application
	Functions     []Function
	HttpAPIs      []HttpAPI
	SimpleTables  []SimpleTable
	StateMachines []StateMachine
}

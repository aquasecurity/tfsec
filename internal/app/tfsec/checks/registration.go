package checks

import (
	"fmt"
	"sync"

	"github.com/hashicorp/hcl/v2"
)

type Check struct {
	RequiredTypes  []string
	RequiredLabels []string
	CheckFunc      func(*hcl.Block, *hcl.EvalContext) []Result
}

var checkLock sync.Mutex
var registeredChecks []Check

func RegisterCheck(check Check) {
	checkLock.Lock()
	defer checkLock.Unlock()
	registeredChecks = append(registeredChecks, check)
}

func GetRegisteredChecks() []Check {
	return registeredChecks
}

func (check *Check) Run(block *hcl.Block, ctx *hcl.EvalContext) []Result {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("WARNING: fatal error running check: %s\n", err)
		}
	}()
	return check.CheckFunc(block, ctx)
}

func (check *Check) IsRequiredForBlock(block *hcl.Block) bool {

	if check.CheckFunc == nil {
		return false
	}

	if len(check.RequiredTypes) > 0 {
		var found bool
		for _, requiredType := range check.RequiredTypes {
			if block.Type == requiredType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(check.RequiredLabels) > 0 {
		var found bool
		for _, requiredLabel := range check.RequiredLabels {
			if len(block.Labels) > 0 && block.Labels[0] == requiredLabel {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

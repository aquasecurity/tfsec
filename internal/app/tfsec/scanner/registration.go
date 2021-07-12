package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aquasecurity/tfsec/pkg/rule"
)

var rulesLock sync.Mutex
var registeredRules []rule.Rule

// RegisterCheckRule registers a new Rule which should be run on future scans
func RegisterCheckRule(rule rule.Rule) {
	if rule.ID == "" {
		panic("rule code was not set")
	}
	rulesLock.Lock()
	defer rulesLock.Unlock()
	for _, existing := range registeredRules {
		if existing.ID == rule.ID {
			panic(fmt.Errorf("rule already exists with code '%s'", rule.ID))
		}
	}
	registeredRules = append(registeredRules, rule)
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID < registeredRules[j].ID
	})
	return registeredRules
}

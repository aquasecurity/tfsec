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
	if rule.LegacyID == "" {
		panic("rule code was not set")
	}
	rulesLock.Lock()
	defer rulesLock.Unlock()
	for _, existing := range registeredRules {
		if existing.LegacyID == rule.LegacyID {
			panic(fmt.Errorf("rule already exists with code '%s'", rule.LegacyID))
		}
	}
	registeredRules = append(registeredRules, rule)
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].LegacyID < registeredRules[j].LegacyID
	})
	return registeredRules
}

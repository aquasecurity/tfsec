package scanner

import (
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/aquasecurity/tfsec/pkg/rule"
)

var rulesLock sync.Mutex
var registeredRules []rule.Rule

// RegisterCheckRule registers a new Rule which should be run on future scans
func RegisterCheckRule(rule rule.Rule) {
	if rule.ShortCode == "" {
		panic("rule short code was not set")
	}
	if rule.Service == "" {
		panic("rule service was not set")
	}
	if rule.Provider == "" {
		panic("rule provider was not set")
	}
	rulesLock.Lock()
	defer rulesLock.Unlock()
	for _, existing := range registeredRules {
		if existing.ID() == rule.ID() {
			fmt.Fprintf(os.Stderr, "Error: rule already exists with code '%s'\n", rule.ID())
			os.Exit(1)
		}
	}
	registeredRules = append(registeredRules, rule)
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

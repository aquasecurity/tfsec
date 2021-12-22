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
	rulesLock.Lock()
	defer rulesLock.Unlock()
	registeredRules = append(registeredRules, rule)
}

func DeregisterCheckRule(r rule.Rule) {
	rulesLock.Lock()
	defer rulesLock.Unlock()
	var filtered []rule.Rule
	for _, existing := range registeredRules {
		if existing.ID() != r.ID() {
			filtered = append(filtered, existing)
		}
	}
	registeredRules = filtered
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

func GetRuleById(ID string) (*rule.Rule, error) {
	for _, r := range registeredRules {
		if r.ID() == ID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with ID '%s'", ID)
}

func GetRuleByLegacyID(legacyID string) (*rule.Rule, error) {
	for _, r := range registeredRules {
		if r.LegacyID == legacyID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with legacyID '%s'", legacyID)
}

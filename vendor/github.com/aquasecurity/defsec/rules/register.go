package rules

import "github.com/aquasecurity/defsec/state"

type CheckFunc func(s *state.State) (results Results)

type RegisteredRule struct {
	rule      Rule
	checkFunc CheckFunc
}

func (r RegisteredRule) Evaluate(s *state.State) Results {
	if r.checkFunc == nil {
		return nil
	}
	results := r.checkFunc(s)
	for i := range results {
		results[i].rule = r.rule
	}
	return results
}

func Register(rule Rule, f CheckFunc) RegisteredRule {
	return RegisteredRule{
		rule:      rule,
		checkFunc: f,
	}
}

func (r RegisteredRule) Rule() Rule {
	return r.rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.rule.Links = append([]string{link}, r.rule.Links...)
}

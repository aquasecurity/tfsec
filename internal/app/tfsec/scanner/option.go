package scanner

import "github.com/aquasecurity/tfsec/pkg/defsec/infra"

type Option func(s *Scanner)

func OptionIncludePassed() func(s *Scanner) {
	return func(s *Scanner) {
		s.includePassed = true
	}
}

func OptionIncludeIgnored() func(s *Scanner) {
	return func(s *Scanner) {
		s.includeIgnored = true
	}
}

func OptionExcludeRules(ruleIDs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.excludedRuleIDs = ruleIDs
	}
}

func OptionIgnoreCheckErrors(ignore bool) func(s *Scanner) {
	return func(s *Scanner) {
		s.ignoreCheckErrors = ignore
	}
}

func OptionWithWorkspaceName(workspaceName string) func(s *Scanner) {
	return func(s *Scanner) {
		s.workspaceName = workspaceName
	}
}

func OptionWithInfrastructure(infra *infra.Context) func(s *Scanner) {
	return func(s *Scanner) {
		s.infra = infra
	}
}

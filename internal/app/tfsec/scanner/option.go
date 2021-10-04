package scanner

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

func OptionIncludeRules(ruleIDs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.includedRuleIDs = ruleIDs
	}
}

func OptionStopOnErrors() func(s *Scanner) {
	return func(s *Scanner) {
		s.ignoreCheckErrors = false
	}
}

func OptionWithWorkspaceName(workspaceName string) func(s *Scanner) {
	return func(s *Scanner) {
		s.workspaceName = workspaceName
	}
}

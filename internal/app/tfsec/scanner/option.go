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

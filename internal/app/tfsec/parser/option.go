package parser

type Option func(p *Parser)

func OptionDoNotSearchTfFiles() Option {
	return func(p *Parser) {
		p.stopOnFirstTf = false
	}
}

func OptionWithTFVarsPath(path string) Option {
	return func(p *Parser) {
		p.tfvarsPath = path
	}
}

func OptionStopOnHCLError() Option {
	return func(p *Parser) {
		p.stopOnHCLError = true
	}
}

package parser

type Option func(p *Parser)

func OptionDoNotSearchTfFiles() Option {
	return func(p *Parser) {
		p.stopOnFirstTf = false
	}
}

func OptionWithTFVarsPaths(paths []string) Option {
	return func(p *Parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError() Option {
	return func(p *Parser) {
		p.stopOnHCLError = true
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *Parser) {
		p.workspaceName = workspaceName
	}
}

func OptionSkipDownloaded() Option {
	return func(p *Parser) {
		p.skipDownloaded = true
	}
}

func OptionWithExcludePaths(paths []string) Option {
	return func(p *Parser) {
		p.excludePaths = paths
	}
}
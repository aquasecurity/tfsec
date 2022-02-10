package parser

type Option func(p *parser)

func OptionDoNotSearchTfFiles() Option {
	return func(p *parser) {
		p.stopOnFirstTf = false
	}
}

func OptionWithTFVarsPaths(paths []string) Option {
	return func(p *parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError() Option {
	return func(p *parser) {
		p.stopOnHCLError = true
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *parser) {
		p.workspaceName = workspaceName
	}
}

func OptionSkipDownloaded() Option {
	return func(p *parser) {
		p.skipDownloaded = true
	}
}

func OptionWithExcludePaths(paths []string) Option {
	return func(p *parser) {
		p.excludePaths = paths
	}
}

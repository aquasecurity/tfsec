package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/tfsec/internal/pkg/formatter"

	"github.com/aquasecurity/tfsec/pkg/scanner"

	"github.com/aquasecurity/defsec/formatters"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/version"
	"github.com/liamg/tml"
)

func output(baseFilename string, formats []string, dir string, results []rules.Result, metrics scanner.Metrics) error {
	if baseFilename == "" && len(formats) > 1 {
		return fmt.Errorf("you must specify a base output filename with --out if you want to use multiple formats")
	}

	var files []string
	for _, format := range formats {
		if filename, err := outputFormat(len(formats) > 1, baseFilename, format, dir, results, metrics); err != nil {
			return err
		} else if filename != "" {
			files = append(files, filename)
		}
	}

	if len(files) > 0 {
		_ = tml.Fprintf(os.Stderr, "<bold>%d file(s) written: %s\n", len(files), strings.Join(files, ", "))
	}

	return nil
}

func gatherLinks(result rules.Result) []string {
	v := "latest"
	if version.Version != "" {
		v = version.Version
	}
	var links []string
	if result.Rule().Terraform != nil {
		links = result.Rule().Terraform.Links
	}

	var docsLink []string
	if result.Rule().Provider == provider.CustomProvider {
		docsLink = result.Rule().Links
	} else {
		docsLink = []string{
			fmt.Sprintf(
				"https://aquasecurity.github.io/tfsec/%s/checks/%s/%s/%s/",
				v,
				result.Rule().Provider,
				strings.ToLower(result.Rule().Service),
				result.Rule().ShortCode,
			),
		}
	}

	return append(docsLink, links...)
}

func outputFormat(addExtension bool, baseFilename string, format string, dir string, results []rules.Result, metrics scanner.Metrics) (string, error) {

	factory := formatters.New().
		WithDebugEnabled(debug).
		WithColoursEnabled(!disableColours).
		WithGroupingEnabled(!disableGrouping).
		WithLinksFunc(gatherLinks).
		WithBaseDir(dir).
		WithMetricsEnabled(!conciseOutput)

	var alsoStdout bool

	switch strings.ToLower(format) {
	case "", "default":
		alsoStdout = true
		factory.WithCustomFormatterFunc(formatter.DefaultWithMetrics(metrics))
	case "json":
		factory.AsJSON()
	case "csv":
		factory.AsCSV()
	case "checkstyle":
		factory.AsCheckStyle()
	case "junit":
		factory.AsJUnit()
	case "text":
		factory.WithCustomFormatterFunc(formatter.DefaultWithMetrics(metrics)).WithColoursEnabled(false)
	case "sarif":
		factory.AsSARIF()
	case "gif":
		factory.WithCustomFormatterFunc(formatter.GifWithMetrics(metrics))
	default:
		return "", fmt.Errorf("invalid format specified: '%s'", format)
	}

	var outputPath string
	if baseFilename != "" {
		if addExtension {
			outputPath = fmt.Sprintf("%s%s", baseFilename, getExtensionForFormat(format))
		} else {
			outputPath = baseFilename
		}
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		if alsoStdout {
			m := io.MultiWriter(f, os.Stdout)
			factory.WithWriter(m)
		} else {
			factory.WithWriter(f)
		}
	}

	return outputPath, factory.Build().Output(results)
}

func getExtensionForFormat(format string) string {
	switch format {
	case "sarif":
		return ".sarif.json"
	case "", "default":
		return ".default.txt"
	case "checkstyle":
		return ".checkstyle.xml"
	default:
		return fmt.Sprintf(".%s", format)
	}
}

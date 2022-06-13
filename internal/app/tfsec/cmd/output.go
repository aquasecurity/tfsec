package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/tfsec/internal/pkg/formatter"
	"github.com/aquasecurity/tfsec/version"
	"github.com/liamg/tml"
)

func output(cmd *cobra.Command, baseFilename string, formats []string, fsRoot, dir string, results []scan.Result, metrics scanner.Metrics) error {
	if baseFilename == "" && len(formats) > 1 {
		return fmt.Errorf("you must specify a base output filename with --out if you want to use multiple formats")
	}

	var files []string
	for _, format := range formats {
		if filename, err := outputFormat(cmd.OutOrStdout(), len(formats) > 1, baseFilename, format, fsRoot, dir, results, metrics); err != nil {
			return err
		} else if filename != "" {
			files = append(files, filename)
		}
	}

	if len(files) > 0 {
		_ = tml.Fprintf(cmd.ErrOrStderr(), "<bold>%d file(s) written: %s\n", len(files), strings.Join(files, ", "))
	}

	return nil
}

func gatherLinks(result scan.Result) []string {
	v := "latest"
	if version.Version != "" {
		v = version.Version
	}
	var links []string
	if result.Rule().Terraform != nil {
		links = result.Rule().Terraform.Links
	}

	var docsLink []string
	if result.Rule().Provider == providers.CustomProvider {
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

// nolint
func outputFormat(w io.Writer, addExtension bool, baseFilename, format, fsRoot, dir string, results scan.Results, metrics scanner.Metrics) (string, error) {

	factory := formatters.New().
		WithDebugEnabled(debug).
		WithColoursEnabled(!disableColours).
		WithGroupingEnabled(!disableGrouping).
		WithLinksFunc(gatherLinks).
		WithFSRoot(fsRoot).
		WithBaseDir(dir).
		WithMetricsEnabled(!conciseOutput).
		WithIncludeIgnored(includeIgnored).
		WithIncludePassed(includePassed)

	var alsoStdout bool
	makeRelative := true

	switch strings.ToLower(format) {
	case "lovely", "default":
		alsoStdout = true
		factory.WithCustomFormatterFunc(formatter.DefaultWithMetrics(metrics, conciseOutput, codeTheme,
			!disableColours, noCode))
	case "json":
		factory.AsJSON()
		makeRelative = false
	case "csv":
		factory.AsCSV()
	case "checkstyle":
		factory.AsCheckStyle()
	case "junit":
		factory.AsJUnit()
	case "text":
		factory.WithCustomFormatterFunc(formatter.DefaultWithMetrics(metrics, conciseOutput, codeTheme, !disableColours, false)).WithColoursEnabled(false)
	case "sarif":
		factory.AsSARIF()
	case "gif":
		factory.WithCustomFormatterFunc(formatter.GifWithMetrics(metrics, codeTheme, !disableColours))
	case "markdown":
		factory.WithCustomFormatterFunc(formatter.Markdown())
	case "html":
		factory.WithCustomFormatterFunc(formatter.HTML())
	default:
		return "", fmt.Errorf("invalid format specified: '%s'", format)
	}

	factory.WithRelativePaths(makeRelative)

	var outputPath string
	if baseFilename != "" {
		if addExtension {
			outputPath = fmt.Sprintf("%s%s", baseFilename, getExtensionForFormat(format))
		} else {
			outputPath = baseFilename
		}
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		if alsoStdout {
			m := io.MultiWriter(f, w)
			factory.WithWriter(m)
		} else {
			factory.WithWriter(f)
		}
	} else {
		factory.WithWriter(w)
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

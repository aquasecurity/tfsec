package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/defsec/formatters"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/aquasecurity/tfsec/version"
	"github.com/liamg/tml"
)

func output(baseFilename string, formats []string, dir string, results []rules.Result) error {
	if baseFilename == "" && len(formats) > 1 {
		return fmt.Errorf("you must specify a base output filename with --out if you want to use multiple formats")
	}

	var files []string
	for _, format := range formats {
		if filename, err := outputFormat(len(formats) > 1, baseFilename, format, dir, results); err != nil {
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

func outputFormat(addExtension bool, baseFilename string, format string, dir string, results []rules.Result) (string, error) {

	formatter := formatters.New().
		WithDebugEnabled(debug.Enabled).
		WithColoursEnabled(!disableColours).
		WithGroupingEnabled(!disableGrouping).
		WithLinksFunc(func(result rules.Result) []string {
			v := "latest"
			if version.Version != "" {
				v = version.Version
			}
			var links []string
			if result.Rule().Terraform != nil {
				links = result.Rule().Terraform.Links
			}
			return append([]string{
				fmt.Sprintf(
					"https://aquasecurity.github.io/tfsec/%s/checks/%s/%s/%s/",
					v,
					result.Rule().Provider,
					strings.ToLower(result.Rule().Service),
					result.Rule().ShortCode,
				),
			}, links...)
		}).
		WithBaseDir(dir).
		WithMetricsEnabled(!conciseOutput)

	var alsoStdout bool

	switch strings.ToLower(format) {
	case "", "default":
		alsoStdout = true
	case "json":
		formatter.AsJSON()
	case "csv":
		formatter.AsCSV()
	case "checkstyle":
		formatter.AsCheckStyle()
	case "junit":
		formatter.AsJUnit()
	case "text":
		formatter.AsDefault().WithColoursEnabled(false)
	case "sarif":
		formatter.AsSARIF()
	case "gif":
		formatter.AsGIF()
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
			formatter.WithWriter(m)
		} else {
			formatter.WithWriter(f)
		}
	}

	return outputPath, formatter.Build().Output(results)
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

package formatter

import (
	scanner "github.com/aquasecurity/defsec/scanners/terraform"

	"github.com/aquasecurity/defsec/formatters"
	"github.com/aquasecurity/defsec/rules"
	"github.com/liamg/gifwrap/pkg/ascii"
)

func GifWithMetrics(metrics scanner.Metrics) func(b formatters.ConfigurableFormatter, results rules.Results) error {
	return func(b formatters.ConfigurableFormatter, results rules.Results) error {

		failCount := len(results.GetFailed())

		gifSrc := "https://media.giphy.com/media/kyLYXonQYYfwYDIeZl/source.gif"

		if failCount > 0 {
			gifSrc = "https://i.giphy.com/media/A1SxC5HRrD3MY/source.gif"
		}

		if renderer, err := ascii.FromURL(gifSrc); err == nil {
			renderer.SetFill(true)
			_ = renderer.PlayOnce()
		}

		return DefaultWithMetrics(metrics, false)(b, results)
	}
}

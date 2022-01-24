package formatters

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/liamg/gifwrap/pkg/ascii"
)

func outputGif(b configurableFormatter, results []rules.Result) error {

	failCount := len(results) - countPassedResults(results)

	gifSrc := "https://media.giphy.com/media/kyLYXonQYYfwYDIeZl/source.gif"

	if failCount > 0 {
		gifSrc = "https://i.giphy.com/media/A1SxC5HRrD3MY/source.gif"
	}

	if renderer, err := ascii.FromURL(gifSrc); err == nil {
		renderer.SetFill(true)
		_ = renderer.PlayOnce()
	}

	return outputDefault(b, results)
}

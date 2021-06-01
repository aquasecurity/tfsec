package externalscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExternal(t *testing.T) {

	example := []string{
		"/blah/tf/main.tf",
		"/blah/tf/modules/main.tf",
		"/blah/tf/modules/something/main.tf",
	}

	results := findTFRootModules(example)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, "/blah/tf", results[0])
}

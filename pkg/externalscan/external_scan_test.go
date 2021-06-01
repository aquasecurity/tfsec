package externalscan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternal(t *testing.T) {

	tmp := os.TempDir()
	testDir := filepath.Join(tmp, fmt.Sprintf("tfsec-test-%d", time.Now().UnixNano()))

	example := []string{
		filepath.Join(testDir, "tf", "main.tf"),
		filepath.Join(testDir, "tf", "modules", "main.tf"),
		filepath.Join(testDir, "tf", "modules", "something", "main.tf"),
	}
	defer os.RemoveAll(testDir)

	for _, path := range example {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		f, err := os.Create(path)
		require.NoError(t, err)
		f.Close()
	}

	results, err := findTFRootModules(example)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, filepath.Join(testDir, "tf"), results[0])
}

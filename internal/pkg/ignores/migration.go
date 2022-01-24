package ignores

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
)

type migrationStatistic struct {
	Filename string
	FromCode string
	ToCode   string
}

type MigrationStatistics []*migrationStatistic

func RunMigration(dir string) (MigrationStatistics, error) {

	legacyMappings := legacy.IDs
	file, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}

	var stats MigrationStatistics
	if file.IsDir() {
		if err := filepath.Walk(dir, func(path string, fsInfo fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if fsInfo.IsDir() {
				return nil
			}
			fileStats, err := migrateFile(path, legacyMappings)
			if err != nil {
				return err
			}
			stats = append(stats, fileStats...)

			return nil
		}); err != nil {
			return nil, err
		}
	} else {
		fileStats, err := migrateFile(dir, legacyMappings)
		if err != nil {
			return nil, err
		}
		stats = append(stats, fileStats...)
	}

	return stats, nil
}

func migrateFile(file string, legacyMapping map[string]string) (MigrationStatistics, error) {
	debug.Log("Asked to migrate %s", file)
	if filepath.Ext(file) != ".tf" {

		return nil, nil
	}

	legacyIgnoreRegex := regexp.MustCompile(`tfsec:ignore:([A-Z]{3}\d{3})`)

	debug.Log("Running migrations for file: %s", file)
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	contentString := string(content)
	var stats MigrationStatistics

	matches := legacyIgnoreRegex.FindAllStringSubmatch(contentString, -1)

	for _, match := range matches {
		legacyCode := match[1]
		newCode := legacy.IDs[legacyCode]
		debug.Log("Found %s, migrating to %s", legacyCode, newCode)
		contentString = strings.ReplaceAll(contentString, legacyCode, newCode)
		stats = append(stats, &migrationStatistic{
			Filename: file,
			FromCode: legacyCode,
			ToCode:   newCode,
		})
	}

	if err := os.WriteFile(file, []byte(contentString), fs.ModeAppend); err != nil {
		return nil, err
	}
	return stats, nil
}

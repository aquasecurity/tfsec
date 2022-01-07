package ignores

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type migrationStatistic struct {
	Filename string
	LineNo   int
	FromCode string
	ToCode   string
}

type MigrationStatistics []*migrationStatistic

func RunMigration(dir string) (MigrationStatistics, error) {

	legacyMappings := getCodeMappings()
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

	debug.Log("Running migrations for file: %s", file)
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	contentString := string(content)
	var stats MigrationStatistics
	for legacyCode, newCode := range legacyMapping {
		legacyIngore := fmt.Sprintf("ignore:%s", legacyCode)
		if strings.Contains(contentString, legacyIngore) {
			lines := strings.Split(contentString, "\n")
			for i, l := range lines {
				if strings.Contains(l, legacyIngore) {
					debug.Log("Found %s, migrating to %s", legacyCode, newCode)
					l = strings.ReplaceAll(l, legacyCode, newCode)
					lines[i] = l
					stats = append(stats, &migrationStatistic{
						Filename: file,
						LineNo:   i + 1,
						FromCode: legacyCode,
						ToCode:   newCode,
					})
				}
			}
			contentString = strings.Join(lines, "\n")
		}
	}
	if err := os.WriteFile(file, []byte(contentString), fs.ModeAppend); err != nil {
		return nil, err
	}
	return stats, nil
}

func getCodeMappings() map[string]string {
	legacyMapping := make(map[string]string)
	rules := scanner.GetRegisteredRules()
	for _, r := range rules {
		if r.LegacyID != "" {
			legacyMapping[r.LegacyID] = r.Base.Rule().LongID()
		}
	}
	return legacyMapping
}

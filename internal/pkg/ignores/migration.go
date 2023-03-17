package ignores

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
)

type migrationStatistic struct {
	Filename string
	FromCode string
	ToCode   string
}

type MigrationStatistics []*migrationStatistic

var renamedMap = map[string]string{
	"aws-elastic-search-encrypt-replication-group":                    "aws-elasticache-enable-at-rest-encryption",
	"aws-elastic-service-enable-domain-encryption":                    "aws-elastic-search-enable-domain-encryption",
	"aws-elbv2-alb-not-public":                                        "aws-elb-alb-not-public",
	"aws-elbv2-http-not-used":                                         "aws-elb-http-not-used",
	"aws-rds-backup-retention-specified":                              "aws-rds-specify-backup-retention",
	"aws-redshift-non-default-vpc-deployment":                         "aws-redshift-use-vpc",
	"aws-workspace-enable-disk-encryption":                            "aws-workspaces-enable-disk-encryption",
	"azure-appservice-enable-https-only":                              "azure-appservice-enforce-https",
	"azure-database-postgres-configuration-log-connection-throttling": "azure-database-postgres-configuration-connection-throttling",
	"azure-mssql-all-threat-alerts-enabled":                           "azure-database-all-threat-alerts-enabled",
	"azure-mssql-threat-alert-email-set":                              "azure-database-threat-alert-email-set",
	"azure-mssql-threat-alert-email-to-owner":                         "azure-database-threat-alert-email-to-owner",
	"digitalocean-droplet-use-ssh-keys":                               "digitalocean-compute-use-ssh-keys",
	"digitalocean-loadbalancing-enforce-https":                        "digitalocean-compute-enforce-https",
	"general-secrets-sensitive-in-attribute":                          "general-secrets-no-plaintext-exposure",
	"general-secrets-sensitive-in-attribute-value":                    "general-secrets-no-plaintext-exposure",
	"general-secrets-sensitive-in-local":                              "general-secrets-no-plaintext-exposure",
	"general-secrets-sensitive-in-variable":                           "general-secrets-no-plaintext-exposure",
	"google-compute-enable-shielded-vm":                               "google-compute-enable-shielded-vm-im",
	"google-compute-no-plaintext-disk-keys":                           "google-compute-disk-encryption-no-plaintext-key",
	"google-compute-no-plaintext-vm-disk-keys":                        "google-compute-disk-encryption-no-plaintext-key",
	"google-gke-no-legacy-auth":                                       "google-gke-no-legacy-authentication",
	"google-project-no-default-network":                               "google-iam-no-default-network",
	"openstack-fw-no-public-access":                                   "openstack-compute-no-public-access",
}

func RunMigration(dir string) (MigrationStatistics, error) {

	legacyMappings := renamedMap
	for from, to := range legacy.IDs {
		legacyMappings[from] = to
	}
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
	fmt.Printf("Asked to migrate %s\n", file)
	if filepath.Ext(file) != ".tf" {

		return nil, nil
	}

	legacyIgnoreRegex := regexp.MustCompile(`tfsec:ignore:([A-Z]{3}\d{3})`)

	fmt.Printf("Running migrations for file: %s\n", file)
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	contentString := string(content)
	var stats MigrationStatistics

	matches := legacyIgnoreRegex.FindAllStringSubmatch(contentString, -1)

	for _, match := range matches {
		legacyCode := match[1]
		newCode, ok := legacyMapping[legacyCode]
		if !ok {
			continue
		}
		fmt.Printf("Found %s, migrating to %s\n", legacyCode, newCode)
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

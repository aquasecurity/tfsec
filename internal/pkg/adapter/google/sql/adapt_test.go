package sql

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/adapter/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.SQL
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.SQL{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []sql.DatabaseInstance
	}{
		{
			name: "all flags",
			terraform: `
resource "google_sql_database_instance" "backup_source_instance" {
  name             = "test-instance"
  database_version = "POSTGRES_11"

  project             = "test-project"
  region              = "europe-west6"
  deletion_protection = false
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = "test-network"
      require_ssl     = true
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_temp_files"
      value = "0"
    }
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
  }
}
                `,
			expected: []sql.DatabaseInstance{
				{
					Metadata:        types.NewTestMetadata(),
					DatabaseVersion: testutil.String("POSTGRES_11"),
					Settings: sql.Settings{
						Backups: sql.Backups{
							Enabled: testutil.Bool(true),
						},
						Flags: sql.Flags{
							LogConnections:                  testutil.Bool(true),
							LogTempFileSize:                 testutil.Int(0),
							LogCheckpoints:                  testutil.Bool(true),
							LogDisconnections:               testutil.Bool(true),
							LogLockWaits:                    testutil.Bool(true),
							ContainedDatabaseAuthentication: testutil.Bool(true),
							CrossDBOwnershipChaining:        testutil.Bool(true),
							LocalInFile:                     testutil.Bool(false),
							LogMinDurationStatement:         testutil.Int(-1),
							LogMinMessages:                  testutil.String(""),
						},
						IPConfiguration: sql.IPConfiguration{
							EnableIPv4: testutil.Bool(false),
							RequireTLS: testutil.Bool(true),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptInstance(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.DatabaseInstance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.DatabaseInstance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptInstance(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFlags(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.Flags
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.Flags{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptFlags(modules.GetBlocks())
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptIPConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.IPConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.IPConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptIPConfig(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIgnoreResults(t *testing.T) {
	src := `resource "aws_lb_listener" "my-lb-listener" {
			port = "80" #tfsec:ignore
			protocol = "HTTPS"
		}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 0)
}

func TestAWSOpenSecurityGroupBad(t *testing.T) {
	src := `
	resource "aws_security_group_rule" "my-rule" {
		type = "ingress"
		cidr_blocks = ["0.0.0.0/0"]
	}
	`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 4, results[0].pos.Line)
}

func TestAWSOpenSecurityGroupGood(t *testing.T) {
	src := `
	resource "aws_security_group_rule" "my-rule" {
		type = "ingress"
		cidr_blocks = ["10.0.0.0/16"]
	}
	`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 0)
}

func TestAWSEC2ClassicBad(t *testing.T) {
	src := `resource "aws_db_security_group" "dbs" {}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 1, results[0].pos.Line)
}

func TestAWSUnencryptedBlockDeviceBad(t *testing.T) {
	src := `resource "aws_launch_configuration" "my-launch-config" {
		ebs_block_device {
			encrypted = "false"
		}
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 3, results[0].pos.Line)
}

func TestAWSUnencryptedBlockDeviceGood(t *testing.T) {
	src := `resource "aws_launch_configuration" "my-launch-config" {
		ebs_block_device {
			encrypted = "true"
		}
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 0)
}

func TestAWSOutdatedSSLPolicyBad(t *testing.T) {
	src := `resource "aws_alb_listener" "my-lb-listener" {
		ssl_policy = "ELBSecurityPolicy-2015-05"
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 2, results[0].pos.Line)
}

func TestAWSInternalBad(t *testing.T) {
	src := `resource "aws_alb" "my-lb" {
		internal = false
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 2, results[0].pos.Line)
}

func TestAWSInternalGood(t *testing.T) {
	src := `resource "aws_alb" "my-lb" {
		internal = true
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 0)
}

func TestAWSPort80Bad(t *testing.T) {
	src := `resource "aws_lb_listener" "my-lb-listener" {
		port = "80"
		protocol = "HTTPS"
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 2, results[0].pos.Line)
}

func TestAWSHTTPBad(t *testing.T) {
	src := `resource "aws_lb_listener" "my-lb-listener" {
		protocol = "HTTP"
	}`
	results, err := Scan([]byte(src))
	require.Nil(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, 2, results[0].pos.Line)
}

package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"

	"github.com/aquasecurity/tfsec/version"
	semver "github.com/hashicorp/go-version"
	"github.com/inconshreveable/go-update"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func Update() (string, error) {
	if version.Version == "" {
		return "", fmt.Errorf("you are running a locally built version")
	}

	latestAvailable, err := getLatestVersion()
	if err != nil {
		return "", err
	}

	updated, err := updateIfNewer(latestAvailable)
	if err != nil {
		return "", err
	}
	if !updated {
		return "", nil
	}
	return latestAvailable, nil
}

func getLatestVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/aquasecurity/tfsec/releases/latest")
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("error occurred when trying to download latest release data")
	}

	defer func() { _ = resp.Body.Close() }()

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	return release.TagName, nil
}

func isNewerVersion(latestVersion string) (bool, error) {
	v1, err := semver.NewVersion(version.Version)
	if err != nil {
		return false, err
	}
	v2, err := semver.NewVersion(latestVersion)
	if err != nil {
		return false, err
	}

	return v1.LessThan(v2), nil
}

func updateIfNewer(latest string) (bool, error) {
	if newer, err := isNewerVersion(latest); err != nil {
		return false, err
	} else if !newer {
		return false, nil
	}
	downloadUrl := resolveDownloadUrl(latest)
	resp, err := http.Get(downloadUrl) //nolint
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failed to download the latest version of tfsec")
	}
	if err := update.Apply(resp.Body, update.Options{}); err != nil {
		return false, err
	}
	return true, nil
}

func resolveDownloadUrl(latest string) string {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}

	return fmt.Sprintf("https://github.com/aquasecurity/tfsec/releases/download/%s/tfsec-%s-%s%s", latest, runtime.GOOS, runtime.GOARCH, suffix)
}

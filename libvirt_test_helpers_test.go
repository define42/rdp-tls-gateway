package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"sync"
	"testing"
)

const legacyDefaultImageDir = "/data/desktop"

var testBaseImageCacheMu sync.Mutex

func newLibvirtAccessibleTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("mkdir temp dir %q: %v", prefix, err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	if settings == nil {
		return
	}
	parsedURL, err := url.Parse(settings.Get(config.BASE_IMAGE_URL))
	if err != nil {
		return
	}
	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return
	}

	sourcePath, ok := findExistingBaseImageSourcePath(imageName)
	if !ok {
		sourcePath = ensureCachedBaseImageSourcePath(t, settings, imageName)
	}
	targetPath := filepath.Join(config.ImageDir(settings), imageName)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("create image dir %s: %v", filepath.Dir(targetPath), err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	if err := os.Link(sourcePath, targetPath); err == nil {
		return
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source base image %s: %v", sourcePath, err)
	}
	defer func() { _ = sourceFile.Close() }()

	targetFile, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("create staged base image %s: %v", targetPath, err)
	}
	defer func() { _ = targetFile.Close() }()

	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		t.Fatalf("copy base image into test root: %v", err)
	}
}

func ensureCachedBaseImageSourcePath(t *testing.T, settings *config.SettingsType, imageName string) string {
	t.Helper()

	cacheDir := filepath.Join(os.TempDir(), "rdptlsgateway-test-base-image-cache")
	cachedPath := filepath.Join(cacheDir, imageName)

	testBaseImageCacheMu.Lock()
	defer testBaseImageCacheMu.Unlock()

	ok, err := nonEmptyFileExists(cachedPath)
	if err != nil {
		t.Fatalf("stat cached base image %s: %v", cachedPath, err)
	}
	if ok {
		return cachedPath
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cached base image dir %s: %v", cacheDir, err)
	}

	baseImageURL := settings.Get(config.BASE_IMAGE_URL)
	resp, err := http.Get(baseImageURL)
	if err != nil {
		t.Fatalf("download cached base image %s: %v", baseImageURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download cached base image %s: unexpected status %s", baseImageURL, resp.Status)
	}

	tmpPath := cachedPath + ".part"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create cached base image %s: %v", tmpPath, err)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		t.Fatalf("copy cached base image %s: %v", tmpPath, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		t.Fatalf("close cached base image %s: %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, cachedPath); err != nil {
		_ = os.Remove(tmpPath)
		t.Fatalf("move cached base image into place %s: %v", cachedPath, err)
	}

	return cachedPath
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
	}
	for _, candidate := range candidates {
		if canUseBaseImageSourcePath(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func canUseBaseImageSourcePath(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func nonEmptyFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return info.Size() > 0, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

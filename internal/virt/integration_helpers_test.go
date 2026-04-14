package virt

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"syscall"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const legacyDefaultImageDir = "/data/desktop"

func newTestLibvirtConn(t *testing.T) *libvirt.Connect {
	t.Helper()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Close()
	})
	return conn
}

func cleanupStoragePool(t *testing.T, name string) {
	t.Helper()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt for cleanup: %v", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	pool, err := conn.LookupStoragePoolByName(name)
	if err != nil {
		return
	}
	defer func() {
		_ = pool.Free()
	}()

	active, err := pool.IsActive()
	if err == nil && active {
		_ = pool.Destroy()
	}
	_ = pool.Undefine()
}

func uniquePoolName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

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

func usePermissiveLibvirtVolumeMode(t *testing.T) {
	t.Helper()
}

func newInitVirtSettings(t *testing.T, rootDir string) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, uniquePoolName("virt-test-pool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	stageExistingBaseImageFromDefaultRoot(t, settings)
	return settings
}

func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	if settings == nil {
		return
	}
	sourcePath := ensureAccessibleBaseImageSourcePath(t, settings.Get(config.BASE_IMAGE_URL))
	if sourcePath == "" {
		return
	}
	stageBootBaseImage(t, sourcePath, filepath.Join(config.ImageDir(settings), filepath.Base(sourcePath)))
}

func ensureAccessibleBaseImageSourcePath(t *testing.T, baseImageURL string) string {
	t.Helper()

	parsedURL, err := url.Parse(baseImageURL)
	if err != nil {
		return ""
	}
	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return ""
	}

	sourcePath, ok := findExistingBaseImageSourcePath(imageName)
	if ok {
		return sourcePath
	}

	return ensureCachedBaseImageSourcePath(t, baseImageURL, imageName)
}

func ensureCachedBaseImageSourcePath(t *testing.T, baseImageURL, imageName string) string {
	t.Helper()

	cacheDir := filepath.Join(os.TempDir(), "rdptlsgateway-test-base-image-cache")
	cachedPath := filepath.Join(cacheDir, imageName)

	withTestBaseImageCacheLock(t, cacheDir, func() {
		ok, err := nonEmptyFileExists(cachedPath)
		if err != nil {
			t.Fatalf("stat cached base image %s: %v", cachedPath, err)
		}
		if ok {
			return
		}

		downloadCachedBaseImage(t, baseImageURL, cachedPath)
	})

	return cachedPath
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
		filepath.Join(os.TempDir(), "rdptlsgateway-test-base-image-cache", imageName),
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

func withTestBaseImageCacheLock(t *testing.T, cacheDir string, fn func()) {
	t.Helper()

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cached base image dir %s: %v", cacheDir, err)
	}

	lockPath := filepath.Join(cacheDir, ".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open cached base image lock %s: %v", lockPath, err)
	}
	defer func() { _ = lockFile.Close() }()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("lock cached base image dir %s: %v", cacheDir, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	fn()
}

func downloadCachedBaseImage(t *testing.T, baseImageURL, cachedPath string) {
	t.Helper()

	resp, err := http.Get(baseImageURL)
	if err != nil {
		t.Fatalf("download cached base image %s: %v", baseImageURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download cached base image %s: unexpected status %s", baseImageURL, resp.Status)
	}

	writeCachedBaseImage(t, cachedPath, resp.Body)
}

func writeCachedBaseImage(t *testing.T, cachedPath string, body io.Reader) {
	t.Helper()

	tmpPath := cachedPath + ".part"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create cached base image %s: %v", tmpPath, err)
	}
	if _, err := io.Copy(out, body); err != nil {
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
}

func newImageServer(t *testing.T, payload []byte, status int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if _, err := w.Write(payload); err != nil {
			t.Errorf("write image payload: %v", err)
		}
	}))
}

func waitForWorkerStop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop in time")
	}
}

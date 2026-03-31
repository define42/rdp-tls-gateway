package virt

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"syscall"
)

func baseImageURLAndPath(settings *config.SettingsType) (string, string, error) {
	baseImageURL := settings.Get(config.BASE_IMAGE_URL)
	parsedURL, err := url.Parse(baseImageURL)
	if err != nil {
		return "", "", fmt.Errorf("parse base image URL %q: %w", baseImageURL, err)
	}

	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return "", "", fmt.Errorf("invalid base image URL %q", baseImageURL)
	}

	imageDir := filepath.Clean(settings.Get(config.VDI_IMAGE_DIR))
	if imageDir == "." {
		return "", "", fmt.Errorf("invalid VDI image directory %q", settings.Get(config.VDI_IMAGE_DIR))
	}

	return baseImageURL, filepath.Join(imageDir, imageName), nil
}

func ensureBaseImage(settings *config.SettingsType) (string, error) {
	baseImageURL, baseImagePath, err := baseImageURLAndPath(settings)
	if err != nil {
		return "", err
	}

	if info, err := os.Stat(baseImagePath); err == nil && info.Size() > 0 {
		return baseImagePath, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("stat base image %s: %w", baseImagePath, err)
	}

	imageDir := filepath.Dir(baseImagePath)
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", fmt.Errorf("create image directory %s: %w", imageDir, err)
	}

	lockFile, err := os.OpenFile(baseImagePath+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return "", fmt.Errorf("open base image lock: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock base image %s: %w", baseImagePath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	if info, err := os.Stat(baseImagePath); err == nil && info.Size() > 0 {
		return baseImagePath, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("stat base image %s after lock: %w", baseImagePath, err)
	}

	tmpFile, err := os.CreateTemp(imageDir, filepath.Base(baseImagePath)+".*.part")
	if err != nil {
		return "", fmt.Errorf("create temporary base image file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temporary base image file: %w", err)
	}
	defer os.Remove(tmpPath)

	log.Printf("Base image %s not found, downloading...", baseImageURL)
	if err := downloadWithProgress(baseImageURL, tmpPath); err != nil {
		return "", fmt.Errorf("download base image: %w", err)
	}
	if err := os.Rename(tmpPath, baseImagePath); err != nil {
		return "", fmt.Errorf("move base image into place: %w", err)
	}

	return baseImagePath, nil
}

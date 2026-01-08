package virt

import (
	"bytes"
	"fmt"
	"os"

	"github.com/kdomanski/iso9660"
)

// SeedISO represents the input required to generate a cloud-init NoCloud ISO
type SeedISO struct {
	UserData []byte
	MetaData []byte
	VolumeID string // defaults to "cidata" if empty
}

// Create writes a NoCloud seed ISO to the given output path
func (s *SeedISO) Create(outputPath string) error {
	if len(s.UserData) == 0 {
		return fmt.Errorf("user-data is required")
	}
	if len(s.MetaData) == 0 {
		return fmt.Errorf("meta-data is required")
	}

	volumeID := s.VolumeID
	if volumeID == "" {
		volumeID = "cidata"
	}

	isoWriter, err := iso9660.NewWriter()
	if err != nil {
		return fmt.Errorf("create iso writer: %w", err)
	}
	defer func() {
		_ = isoWriter.Cleanup()
	}()

	// cloud-init requires exact filenames
	if err := isoWriter.AddFile(bytes.NewReader(s.UserData), "user-data"); err != nil {
		return fmt.Errorf("add user-data: %w", err)
	}

	if err := isoWriter.AddFile(bytes.NewReader(s.MetaData), "meta-data"); err != nil {
		return fmt.Errorf("add meta-data: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	if err := isoWriter.WriteTo(f, volumeID); err != nil {
		return fmt.Errorf("write iso: %w", err)
	}

	return nil
}

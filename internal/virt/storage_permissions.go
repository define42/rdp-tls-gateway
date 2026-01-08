package virt

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"libvirt.org/go/libvirt"
)

const (
	volumeModeEnv  = "LIBVIRT_VOLUME_MODE"
	volumeOwnerEnv = "LIBVIRT_VOLUME_OWNER"
	volumeGroupEnv = "LIBVIRT_VOLUME_GROUP"
)

type storagePoolXML struct {
	Target struct {
		Path string `xml:"path"`
	} `xml:"target"`
}

func storageVolPermissionsXML() (string, error) {
	ownerXML, err := envUintXML(volumeOwnerEnv, "owner", 10)
	if err != nil {
		return "", err
	}
	groupXML, err := envUintXML(volumeGroupEnv, "group", 10)
	if err != nil {
		return "", err
	}
	modeXML, err := envModeXML()
	if err != nil {
		return "", err
	}
	if ownerXML == "" && groupXML == "" && modeXML == "" {
		return "", nil
	}
	return fmt.Sprintf("\n    <permissions>%s%s%s\n    </permissions>", ownerXML, groupXML, modeXML), nil
}

func storageVolPathXML(pool *libvirt.StoragePool, volumeName string) (string, error) {
	poolPath, err := storagePoolTargetPath(pool)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("\n    <path>%s</path>", filepath.Join(poolPath, volumeName)), nil
}

func storagePoolTargetPath(pool *libvirt.StoragePool) (string, error) {
	xmlDesc, err := pool.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf("get storage pool xml: %w", err)
	}
	var parsed storagePoolXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", fmt.Errorf("parse storage pool xml: %w", err)
	}
	path := strings.TrimSpace(parsed.Target.Path)
	if path == "" {
		return "", fmt.Errorf("storage pool target path not found")
	}
	return path, nil
}

func envModeXML() (string, error) {
	modeStr := strings.TrimSpace(os.Getenv(volumeModeEnv))
	if modeStr == "" {
		return "", nil
	}
	modeStr = strings.TrimPrefix(modeStr, "0o")
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", volumeModeEnv, modeStr, err)
	}
	return fmt.Sprintf("\n      <mode>%04o</mode>", mode), nil
}

func envUintXML(envVar, tag string, base int) (string, error) {
	raw := strings.TrimSpace(os.Getenv(envVar))
	if raw == "" {
		return "", nil
	}
	val, err := strconv.ParseUint(raw, base, 32)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", envVar, raw, err)
	}
	return fmt.Sprintf("\n      <%s>%d</%s>", tag, val, tag), nil
}

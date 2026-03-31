package virt

import (
	"os"
	"strings"
)

const (
	defaultLibvirtURI = "qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock"
	libvirtURIEnv     = "LIBVIRT_URI"
)

// LibvirtURI returns the configured libvirt connection URI.
func LibvirtURI() string {
	if uri := strings.TrimSpace(os.Getenv(libvirtURIEnv)); uri != "" {
		return uri
	}
	return defaultLibvirtURI
}

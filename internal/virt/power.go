package virt

import (
	"fmt"

	"libvirt.org/go/libvirt"
)

// StartExistingVM starts an existing domain when it is currently shut off.
func StartExistingVM(name string) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if active {
		return nil
	}
	if err := cleanupDomainSerialSocket(dom); err != nil {
		return fmt.Errorf("cleanup serial socket for %s: %w", name, err)
	}
	if err := cleanupDomainVNCSocket(dom); err != nil {
		return fmt.Errorf("cleanup vnc socket for %s: %w", name, err)
	}
	if err := dom.Create(); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	return nil
}

// ShutdownVM force-stops a running domain.
func ShutdownVM(name string) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return nil
	}
	if err := dom.Destroy(); err != nil {
		return fmt.Errorf("force shutdown domain %s: %w", name, err)
	}
	return nil
}

// RestartVM reboots a running domain or starts it when it is shut off.
func RestartVM(name string) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if active {
		if err := dom.Reboot(0); err != nil {
			return fmt.Errorf("reboot domain %s: %w", name, err)
		}
		return nil
	}
	if err := cleanupDomainSerialSocket(dom); err != nil {
		return fmt.Errorf("cleanup serial socket for %s: %w", name, err)
	}
	if err := cleanupDomainVNCSocket(dom); err != nil {
		return fmt.Errorf("cleanup vnc socket for %s: %w", name, err)
	}
	if err := dom.Create(); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	return nil
}

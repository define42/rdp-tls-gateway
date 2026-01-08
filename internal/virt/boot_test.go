package virt_test

import (
	"log"
	"rdptlsgateway/internal/config"
	typesUser "rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"testing"
)

const (
	testVMName   = "test-vm"
	testUsername = "testuser"
	testPassword = "dogood"
)

func TestStartVM(t *testing.T) {

	settings := config.NewSettingType(false)

	if err := virt.InitVirt(settings); err != nil {
		log.Fatalf("Failed to initialize virtualization: %v", err)
	}

	user, err := typesUser.NewUser(testUsername, testPassword, "")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	vmName, err := virt.BootNewVM(testVMName, user, settings)
	if err != nil {
		t.Fatalf("Failed to boot new VM %s: %v", vmName, err)
	}

	vms, err := virt.ListVMs(testUsername)
	if err != nil {
		t.Fatalf("Failed to list VMs: %v", err)
	}

	// Verify that the VM is in the list
	found := false
	for _, v := range vms {
		if v.Name == vmName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Booted VM %s not found in VM list", vmName)
	}

	// Cleanup: Destroy the VM after test
	// (In a real test, consider using defer to ensure cleanup)
	err = virt.RemoveVM(vmName)
	if err != nil {
		t.Fatalf("Failed to destroy VM %s: %v", vmName, err)
	}

	// Verify that the VM has been removed
	vms, err = virt.ListVMs("")
	if err != nil {
		t.Fatalf("Failed to list VMs after deletion: %v", err)
	}
	for _, v := range vms {
		if v.Name == vmName {
			t.Fatalf("VM %s still found in VM list after deletion", vmName)
		}
	}
}

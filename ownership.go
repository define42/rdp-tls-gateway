package main

import (
	"rdptlsgateway/internal/virt"
	"strings"
)

func dashboardVMOwnershipCheck(name, username string) (bool, error) {
	owner, hasOwner, err := virt.VMOwner(name)
	if err != nil {
		return false, err
	}
	return dashboardVMOwnedByUser(owner, hasOwner, username), nil
}

func dashboardVMOwnedByUser(owner string, hasOwner bool, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" || !hasOwner {
		return false
	}
	return strings.TrimSpace(owner) == username
}

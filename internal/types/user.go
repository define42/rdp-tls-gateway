// Package types defines shared data structures used across the gateway.
package types

import "rdptlsgateway/internal/hash"

// User represents an authenticated gateway user.
type User struct {
	Name                  string
	CloudInitPasswordHash string
}

// NewUser creates a user and derives the cloud-init password hash.
func NewUser(name, password string) (*User, error) {
	cloudInitPassword, err := hash.CloudInitPasswordHash(password)
	if err != nil {
		return nil, err
	}

	return &User{
		Name:                  name,
		CloudInitPasswordHash: cloudInitPassword,
	}, nil
}

// GetName returns the username.
func (u *User) GetName() string {
	return u.Name
}

// GetCloudInitPasswordHash returns the cloud-init compatible password hash.
func (u *User) GetCloudInitPasswordHash() string {
	return u.CloudInitPasswordHash
}

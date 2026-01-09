package types

import "rdptlsgateway/internal/hash"

type User struct {
	Name                  string
	CloudInitPasswordHash string
}

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

func (u *User) GetName() string {
	return u.Name
}

func (u *User) GetCloudInitPasswordHash() string {
	return u.CloudInitPasswordHash
}

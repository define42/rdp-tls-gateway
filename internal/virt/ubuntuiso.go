package virt

import (
	"bytes"
	"fmt"

	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

// CreateUbuntuSeedISOToPool builds a cloud-init seed ISO and uploads it to the storage pool.
func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {
	userData, metaData, networkConfig := ubuntuSeedData(username, cloudInitPasswordHash, hostname)
	seedISOData, err := CreateSeedISO(userData, metaData, networkConfig)
	if err != nil {
		return err
	}

	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	volXML, err := storageVolCreateXML(pool, volumeName, uint64(len(seedISOData)), "raw")
	if err != nil {
		return err
	}

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	return uploadSeedISO(conn, vol, seedISOData)
}

func ubuntuSeedData(username, cloudInitPasswordHash, hostname string) (*SeedUserData, *SeedMetaData, *SeedNetworkConfig) {
	userData := &SeedUserData{
		Output: &SeedOutput{
			All: "| tee -a /var/log/cloud-init-output.log",
		},
		Keyboard: &SeedKeyboard{
			Layout:  "dk",
			Variant: "",
		},
		Users: []SeedUser{
			{
				Name:       username,
				Sudo:       "ALL=(ALL) NOPASSWD:ALL",
				Shell:      "/bin/bash",
				LockPasswd: false,
				Passwd:     cloudInitPasswordHash,
			},
		},
		SSHPwAuth: true,
		RunCmd: []string{
			"systemctl enable --now serial-getty@ttyS0.service",
		},
	}

	metaData := &SeedMetaData{
		InstanceID:    uuid.New().String(),
		LocalHostname: hostname,
	}

	networkConfig := &SeedNetworkConfig{
		Network: SeedNetwork{
			Version: 2,
			Ethernets: SeedEthernets{
				All: SeedEthernet{
					Match: &SeedInterfaceMatch{
						Name: "en*",
					},
					DHCP4:    true,
					DHCP6:    false,
					AcceptRA: false,
				},
			},
		},
	}

	return userData, metaData, networkConfig
}

func uploadSeedISO(conn *libvirt.Connect, vol *libvirt.StorageVol, seedISOData []byte) error {
	stream, err := conn.NewStream(0)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Free()
	}()

	if err := vol.Upload(stream, 0, uint64(len(seedISOData)), 0); err != nil {
		return err
	}

	if err := stream.SendAll(streamReaderChunks(bytes.NewReader(seedISOData))); err != nil {
		_ = stream.Abort()
		return err
	}

	return stream.Finish()
}

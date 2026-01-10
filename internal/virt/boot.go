package virt

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"

	"libvirt.org/go/libvirt"
)

const (
	// LibvirtURI is the URI used to connect to libvirt
	DEFAULT_VIRT_STORAGE = "default"
	//BASE_IMAGE           = "noble-desktop-cloudimg-amd64.img"

	//BASE_IMAGE_URL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
)

// startVM starts a libvirt VM by name if it is not already running

func StartVM(name, seedIso string, vcpu int, memoryMiB int) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return err
	}
	defer conn.Close()

	dom, err := conn.DomainDefineXML(UbuntuDomain(name, seedIso, vcpu, memoryMiB))
	if err != nil {
		fmt.Println("whaat", err)
		return err
	}
	defer func() {
		_ = dom.Free()
	}()

	if err := dom.Create(); err != nil {
		return err
	}

	//fmt.Printf("VM %s started (ID %d)\n", name, dom.GetID())
	return nil

}

func RemoveVolumes(conn *libvirt.Connect, volumeNames ...string) error {
	pool, err := conn.LookupStoragePoolByName(DEFAULT_VIRT_STORAGE)
	if err != nil {
		return fmt.Errorf("lookup storage pool: %w", err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	for _, volumeName := range volumeNames {
		vol, err := pool.LookupStorageVolByName(volumeName)
		if err != nil {
			continue
		}
		defer func() {
			_ = vol.Free()
		}()

		if err := vol.Delete(0); err != nil {
			return fmt.Errorf("delete volume %s: %w", volumeName, err)
		}
		log.Printf("Deleted volume %s", volumeName)
	}

	return nil
}

func CopyAndResizeVolume(
	conn *libvirt.Connect,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {

	// Lookup storage pool
	pool, err := conn.LookupStoragePoolByName(DEFAULT_VIRT_STORAGE)
	if err != nil {
		return fmt.Errorf("lookup pool: %w", err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// Create volume XML
	permXML, err := storageVolPermissionsXML()
	if err != nil {
		return err
	}
	pathXML := ""
	if permXML != "" {
		pathXML, err = storageVolPathXML(pool, volumeName)
		if err != nil {
			return err
		}
	}
	volXML := fmt.Sprintf(`
<volume>
  <name>%s</name>
  <capacity unit="bytes">%d</capacity>
  <target>
    <format type="qcow2"/>%s%s
  </target>
</volume>`, volumeName, capacityBytes, pathXML, permXML)

	// Create volume
	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return fmt.Errorf("create volume: %w", err)
	}
	defer func() {
		_ = vol.Free()
	}()

	// Open source image
	src, err := os.Open(sourceImagePath)
	if err != nil {
		return fmt.Errorf("open source image: %w", err)
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat source image: %w", err)
	}

	// Create libvirt stream
	stream, err := conn.NewStream(0)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	defer func() {
		_ = stream.Free()
	}()

	// Start upload
	if err := vol.Upload(stream, 0, uint64(srcInfo.Size()), 0); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}

	if err := stream.SendAll(func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		if nbytes <= 0 {
			return []byte{}, nil
		}
		buf := make([]byte, nbytes)
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				if n == 0 {
					return []byte{}, nil
				}
				return buf[:n], nil
			}
			return nil, err
		}
		if n == 0 {
			return []byte{}, nil
		}
		return buf[:n], nil
	}); err != nil {
		_ = stream.Abort()
		return fmt.Errorf("stream send: %w", err)
	}

	if err := stream.Finish(); err != nil {
		return fmt.Errorf("stream finish: %w", err)
	}

	if capacityBytes > 0 {
		volInfo, err := vol.GetInfo()
		if err != nil {
			return fmt.Errorf("get volume info: %w", err)
		}
		if volInfo.Capacity < capacityBytes {
			if err := vol.Resize(capacityBytes, 0); err != nil {
				return fmt.Errorf("resize volume: %w", err)
			}
		}
	}

	return nil
}

func DestroyExistingDomain(conn *libvirt.Connect, vmName string) error {
	existingDom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil
	}
	defer func() {
		_ = existingDom.Free()
	}()

	active, err := existingDom.IsActive()
	if err != nil {
		return err
	}
	if active {
		if err := existingDom.Destroy(); err != nil {
			return err
		}
		log.Printf("Destroyed running domain %s", vmName)
	}

	if err := existingDom.Undefine(); err != nil {
		return err
	}
	log.Printf("Undefined domain %s", vmName)
	return nil
}

func InitVirt(settings *config.SettingsType) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("Failed to connect to libvirt: %v", err)
	}
	defer conn.Close()

	baseImageUrl := settings.Get(config.BASE_IMAGE_URL)

	u, err := url.Parse(baseImageUrl)
	if err != nil {
		return fmt.Errorf("Failed to parse base image URL: %v", err)
	}
	base_image := path.Base(u.Path)

	pool, err := conn.LookupStoragePoolByName(DEFAULT_VIRT_STORAGE)
	if err != nil {
		return fmt.Errorf("Failed to lookup storage pool %s: %v", DEFAULT_VIRT_STORAGE, err)
	}
	defer func() {
		_ = pool.Free()
	}()

	active, err := pool.IsActive()
	if err != nil {
		return fmt.Errorf("Failed to check if storage pool %s is active: %v", DEFAULT_VIRT_STORAGE, err)
	}
	if !active {
		if err := pool.Create(0); err != nil {
			return fmt.Errorf("Failed to create storage pool %s: %v", DEFAULT_VIRT_STORAGE, err)
		}
		log.Printf("Storage pool %s started", DEFAULT_VIRT_STORAGE)
	}

	baseImage := settings.Get(config.VDI_IMAGE_DIR) + "/" + base_image

	// check image exists
	if _, err := os.Stat(baseImage); os.IsNotExist(err) {

		if err := os.MkdirAll(settings.Get(config.VDI_IMAGE_DIR), 0755); err != nil {
			return fmt.Errorf("Failed to create image directory: %v", err)
		}

		log.Printf("Base image %s not found, downloading...", baseImageUrl)
		if err := downloadWithProgress(baseImageUrl, baseImage); err != nil {
			return fmt.Errorf("Failed to download base image: %v", err)
		}
	}

	return nil
}

func BootNewVM(name string, user *types.User, settings *config.SettingsType, vcpu int, memoryMiB int) (vmName string, err error) {

	vmName = user.GetName() + "-" + name
	if vcpu <= 0 || memoryMiB <= 0 {
		return vmName, fmt.Errorf("invalid resources (vcpu=%d memoryMiB=%d)", vcpu, memoryMiB)
	}

	seedIso := vmName + "_seed.iso"

	baseImageUrl := settings.Get(config.BASE_IMAGE_URL)

	u, err := url.Parse(baseImageUrl)
	if err != nil {
		return vmName, fmt.Errorf("Failed to parse base image URL: %v", err)
	}
	base_image := path.Base(u.Path)

	baseImage := settings.Get(config.VDI_IMAGE_DIR) + "/" + base_image

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return vmName, fmt.Errorf("Failed to connect to libvirt: %v", err)
	}
	defer conn.Close()

	if err := DestroyExistingDomain(conn, vmName); err != nil {
		return vmName, fmt.Errorf("Failed to destroy existing domain: %v", err)
	}
	if err := RemoveVolumes(conn, vmName, seedIso); err != nil {
		return vmName, fmt.Errorf("Failed to remove existing volumes: %v", err)
	}

	if err := CopyAndResizeVolume(conn, vmName, baseImage, 40*1024*1024*1024); err != nil {
		return vmName, fmt.Errorf("Failed to copy and resize base image: %v", err)
	}

	if err := CreateUbuntuSeedISOToPool(conn, seedIso, user.GetName(), user.GetCloudInitPasswordHash(), vmName); err != nil {
		return vmName, fmt.Errorf("Failed to create seed ISO: %v", err)
	}

	if err := StartVM(vmName, seedIso, vcpu, memoryMiB); err != nil {
		return vmName, fmt.Errorf("Failed to start VM: %v", err)
	}

	return vmName, nil
}

func RemoveVM(name string) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := DestroyExistingDomain(conn, name); err != nil {
		return err
	}
	seedIso := name + "_seed.iso"
	if err := RemoveVolumes(conn, name, seedIso); err != nil {
		return err
	}
	return nil
}

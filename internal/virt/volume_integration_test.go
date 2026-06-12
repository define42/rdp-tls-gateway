package virt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyAndResizeVolumeAndRemoveVolumes(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("copy-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	sourceImage := filepath.Join(t.TempDir(), "source.img")
	if err := os.WriteFile(sourceImage, []byte("tiny-volume"), 0o644); err != nil {
		t.Fatalf("write source image: %v", err)
	}

	if err := CopyAndResizeVolume(conn, poolName, "vmdisk", sourceImage, 2*1024*1024); err != nil {
		t.Fatalf("CopyAndResizeVolume: %v", err)
	}

	vol, err := pool.LookupStorageVolByName("vmdisk")
	if err != nil {
		t.Fatalf("lookup copied volume: %v", err)
	}
	volPath, err := vol.GetPath()
	if err != nil {
		_ = vol.Free()
		t.Fatalf("get copied volume path: %v", err)
	}
	info, err := vol.GetInfo()
	if err != nil {
		_ = vol.Free()
		t.Fatalf("get copied volume info: %v", err)
	}
	_ = vol.Free()
	if info.Capacity < 2*1024*1024 {
		t.Fatalf("expected resized capacity >= 2 MiB, got %d", info.Capacity)
	}
	stat, err := os.Stat(volPath)
	if err != nil {
		t.Fatalf("stat copied volume path: %v", err)
	}
	if got := stat.Mode().Perm(); got != 0o660 {
		t.Fatalf("expected copied volume mode %04o, got %04o", 0o660, got)
	}

	if err := RemoveVolumes(conn, poolName, "vmdisk"); err != nil {
		t.Fatalf("RemoveVolumes: %v", err)
	}
	if _, err := pool.LookupStorageVolByName("vmdisk"); err == nil {
		t.Fatal("expected copied volume to be removed")
	}
}

func TestCopyAndResizeVolumeMissingSource(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("missing-source-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if _, err := ensureStoragePool(conn, poolName, poolPath); err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}

	err := CopyAndResizeVolume(conn, poolName, "vmdisk", filepath.Join(t.TempDir(), "missing.img"), 1024)
	if err == nil {
		t.Fatal("expected missing source image error")
	}
}

func TestRemoveVolumesIgnoresMissingVolumes(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("remove-missing-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if _, err := ensureStoragePool(conn, poolName, poolPath); err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}

	if err := RemoveVolumes(conn, poolName, "missing-volume"); err != nil {
		t.Fatalf("expected missing volumes to be ignored, got %v", err)
	}
}

func TestDestroyExistingDomainMissingDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	if err := DestroyExistingDomain(conn, "missing-domain-for-test"); err != nil {
		t.Fatalf("expected missing domain cleanup to succeed, got %v", err)
	}
}

package virt

import (
	"fmt"
	"sync"
	"testing"
)

func TestSingletonWorkerDoWorkNilConn(t *testing.T) {
	worker := &SingletonWorker{}
	if err := worker.doWork(nil); err == nil {
		t.Fatal("expected error for nil libvirt connection")
	}
}

func TestSingletonWorkerCacheConcurrentAccess(t *testing.T) {
	worker := &SingletonWorker{}

	const loops = 500
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			worker.setVMs([]vmInfo{
				{
					Name:      fmt.Sprintf("alice-vm-%d", i),
					PrimaryIP: "10.0.0.1",
				},
				{
					Name:      fmt.Sprintf("bob-vm-%d", i),
					PrimaryIP: "10.0.0.2",
				},
			})
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			_ = worker.GetVMs("alice")
			_ = worker.GetVMnames()
			_, _ = worker.GetIpOfVm(fmt.Sprintf("alice-vm-%d", i))
		}
	}()

	wg.Wait()
}

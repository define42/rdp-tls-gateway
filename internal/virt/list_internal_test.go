package virt

import "testing"

func TestSingletonWorkerDoWorkNilConn(t *testing.T) {
	worker := &SingletonWorker{}
	if err := worker.doWork(nil); err == nil {
		t.Fatal("expected error for nil libvirt connection")
	}
}

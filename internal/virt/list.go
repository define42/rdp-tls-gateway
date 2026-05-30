package virt

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"libvirt.org/go/libvirt"
)

// VMInfo describes a VM entry shown in the dashboard and worker cache.
type VMInfo struct {
	Name      string
	Owner     string
	GuestUser string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
	IP        string
	PrimaryIP string
	TTYReady  bool
	VNCReady  bool
}

// ListVMs returns VMs visible to the given user from the provided libvirt connection.
func ListVMs(user string, conn *libvirt.Connect) ([]VMInfo, error) {
	doms, err := conn.ListAllDomains(0)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer freeDomains(doms)

	var result []VMInfo
	for _, d := range doms {
		info, ok := domainVMInfo(d, user)
		if ok {
			result = append(result, info)
		}
	}
	return result, nil
}

func freeDomains(doms []libvirt.Domain) {
	for _, d := range doms {
		_ = d.Free()
	}
}

func domainVMInfo(d libvirt.Domain, user string) (VMInfo, bool) {
	name, err := d.GetName()
	if err != nil {
		log.Printf("domain name: %v", err)
		return VMInfo{}, false
	}

	owner := domainOwnerForVMInfo(name, &d)
	if user != "" && owner != user {
		return VMInfo{}, false
	}

	state, _, err := d.GetState()
	if err != nil {
		log.Printf("domain state %s: %v", name, err)
		return VMInfo{}, false
	}

	mem, vcpu := domainResources(d)
	ip, primaryIP := domainDisplayIPs(d, state)
	return VMInfo{
		Name:      name,
		Owner:     owner,
		GuestUser: domainGuestUserForVMInfo(name, &d),
		State:     formatState(state),
		MemoryMiB: mem,
		VCPU:      vcpu,
		VolumeGB:  domainDiskGB(d),
		IP:        ip,
		PrimaryIP: primaryIP,
		TTYReady:  domainTTYReady(&d),
		VNCReady:  domainVNCReady(&d),
	}, true
}

func domainOwnerForVMInfo(name string, d *libvirt.Domain) string {
	owner, hasOwner, err := domainOwner(d)
	if err != nil {
		log.Printf("domain owner %s: %v", name, err)
		return ""
	}
	if !hasOwner {
		return ""
	}
	return owner
}

func domainGuestUserForVMInfo(name string, d *libvirt.Domain) string {
	guestUser, hasGuestUser, err := domainGuestUser(d)
	if err != nil {
		log.Printf("domain guest user %s: %v", name, err)
		return ""
	}
	if !hasGuestUser {
		return ""
	}
	return guestUser
}

func domainDisplayIPs(d libvirt.Domain, state libvirt.DomainState) (string, string) {
	if !domainCanReportIPs(state) {
		return "", ""
	}

	ips := domainIPs(d)
	if len(ips) == 0 {
		return "", ""
	}

	return strings.Join(ips, ", "), ips[0]
}

func domainCanReportIPs(state libvirt.DomainState) bool {
	switch state {
	case libvirt.DOMAIN_RUNNING, libvirt.DOMAIN_PAUSED, libvirt.DOMAIN_PMSUSPENDED:
		return true
	case libvirt.DOMAIN_NOSTATE, libvirt.DOMAIN_BLOCKED, libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_CRASHED, libvirt.DOMAIN_SHUTOFF:
		return false
	default:
		return false
	}
}

func domainTTYReady(d *libvirt.Domain) bool {
	_, ok, err := domainSerialSocketPath(d)
	if err != nil {
		log.Printf("domain tty readiness: %v", err)
		return false
	}
	return ok
}

func domainVNCReady(d *libvirt.Domain) bool {
	_, ok, err := domainVNCSocketPath(d)
	if err != nil {
		log.Printf("domain vnc readiness: %v", err)
		return false
	}
	return ok
}

func domainResources(d libvirt.Domain) (int, int) {
	info, err := d.GetInfo()
	if err != nil {
		log.Printf("domain info: %v", err)
		return 0, 0
	}
	memMiB := int(info.Memory / 1024)
	return memMiB, int(info.NrVirtCpu)
}

func domainDiskGB(d libvirt.Domain) int {
	info, err := d.GetBlockInfo("vda", 0)
	if err != nil {
		return 0
	}
	size := info.Capacity
	if size == 0 {
		size = info.Physical
	}
	if size == 0 {
		size = info.Allocation
	}
	if size == 0 {
		return 0
	}
	return int((size + (1 << 30) - 1) >> 30)
}

func domainIPs(d libvirt.Domain) []string {
	sources := []libvirt.DomainInterfaceAddressesSource{
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_ARP,
	}

	var ips []string
	seen := make(map[string]struct{})

	for _, src := range sources {
		ips = appendDomainIPsFromSource(ips, seen, d, src)
	}
	return ips
}

func appendDomainIPsFromSource(ips []string, seen map[string]struct{}, d libvirt.Domain, src libvirt.DomainInterfaceAddressesSource) []string {
	ifaces, err := d.ListAllInterfaceAddresses(src)
	if err != nil {
		return ips
	}

	for _, iface := range ifaces {
		ips = appendDomainInterfaceIPs(ips, seen, iface)
	}
	return ips
}

func appendDomainInterfaceIPs(ips []string, seen map[string]struct{}, iface libvirt.DomainInterface) []string {
	for _, addr := range iface.Addrs {
		ips = appendUniqueDomainIP(ips, seen, addr.Addr)
	}
	return ips
}

func appendUniqueDomainIP(ips []string, seen map[string]struct{}, addr string) []string {
	if addr == "" {
		return ips
	}
	if _, ok := seen[addr]; ok {
		return ips
	}
	seen[addr] = struct{}{}
	return append(ips, addr)
}

func formatState(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_NOSTATE:
		return "unknown"
	case libvirt.DOMAIN_BLOCKED:
		return "blocked"
	case libvirt.DOMAIN_RUNNING:
		return "running"
	case libvirt.DOMAIN_PAUSED:
		return "paused"
	case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF:
		return "shut off"
	case libvirt.DOMAIN_CRASHED:
		return "crashed"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "suspended"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}

// SingletonWorker caches VM metadata in the background for fast read access.
type SingletonWorker struct {
	ticker *time.Ticker
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
	vms    []VMInfo
}

// GetVMs returns the cached VMs, optionally filtered by owner.
func (s *SingletonWorker) GetVMs(user string) []VMInfo {
	snapshot := s.snapshotVMs()

	var filteredVMs []VMInfo
	for _, vm := range snapshot {
		if user == "" || vm.Owner == user {
			filteredVMs = append(filteredVMs, vm)
		}
	}
	return filteredVMs
}

// GetVMnames returns the cached VM names.
func (s *SingletonWorker) GetVMnames() []string {
	snapshot := s.snapshotVMs()

	var names []string
	for _, vm := range snapshot {
		names = append(names, vm.Name)
	}
	return names
}

// GetIPOfVM returns the primary IP address cached for the named VM.
func (s *SingletonWorker) GetIPOfVM(vmName string) (string, error) {
	for _, vm := range s.snapshotVMs() {
		if vm.Name == vmName {
			return vm.PrimaryIP, nil
		}
	}
	return "", fmt.Errorf("vm %s not found", vmName)
}

func (s *SingletonWorker) snapshotVMs() []VMInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.vms) == 0 {
		return nil
	}

	snapshot := make([]VMInfo, len(s.vms))
	copy(snapshot, s.vms)
	return snapshot
}

func (s *SingletonWorker) setVMs(vms []VMInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(vms) == 0 {
		s.vms = nil
		return
	}

	next := make([]VMInfo, len(vms))
	copy(next, vms)
	s.vms = next
}

var (
	instance *SingletonWorker //nolint:gochecknoglobals // package-level singleton needed for one-time registration
	once     sync.Once        //nolint:gochecknoglobals // package-level singleton needed for one-time registration
)

// GetInstance returns the process-wide VM cache worker.
func GetInstance() *SingletonWorker {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		instance = &SingletonWorker{
			ticker: time.NewTicker(2 * time.Second),
			ctx:    ctx,
			cancel: cancel,
		}

		go instance.run()
	})

	return instance
}

func (s *SingletonWorker) run() {
	log.Println("singleton worker started")

	var conn *libvirt.Connect
	defer func() {
		if conn != nil {
			_, _ = conn.Close()
		}
	}()

	for {
		select {
		case <-s.ticker.C:
			if conn == nil {
				var err error
				conn, err = libvirt.NewConnect(LibvirtURI())
				if err != nil {
					log.Printf("list vms connect: %v", err)
					continue
				}
			}

			if err := s.doWork(conn); err != nil {
				log.Printf("singleton worker list vms: %v", err)
				_, _ = conn.Close()
				conn = nil
			}
		case <-s.ctx.Done():
			log.Println("singleton worker stopped")
			return
		}
	}
}

func (s *SingletonWorker) doWork(conn *libvirt.Connect) error {
	log.Println("doing work every 2 seconds")
	if conn == nil {
		return fmt.Errorf("libvirt connection is nil")
	}

	vms, err := ListVMs("", conn)
	if err != nil {
		return err
	}
	s.setVMs(vms)
	return nil
}

// Stop stops the background worker ticker and cancels its context.
func (s *SingletonWorker) Stop() {
	s.cancel()
	s.ticker.Stop()
}

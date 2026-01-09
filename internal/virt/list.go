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

type vmInfo struct {
	Name      string
	State     string
	MemoryMiB int
	VCPU      int
	VolumeGB  int
	IP        string
	PrimaryIP string
}

func ListVMs(prefix string) ([]vmInfo, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		log.Printf("list vms connect: %v", err)
		return nil, err
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(0)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer func() {
		for _, d := range doms {
			_ = d.Free()
		}
	}()

	var result []vmInfo
	for _, d := range doms {
		name, err := d.GetName()
		if err != nil {
			log.Printf("domain name: %v", err)
			continue
		}
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}

		state, _, err := d.GetState()
		if err != nil {
			log.Printf("domain state %s: %v", name, err)
			continue
		}
		mem, vcpu := domainResources(d)
		volGB := domainDiskGB(d)
		ip := ""
		primaryIP := ""
		if state == libvirt.DOMAIN_RUNNING || state == libvirt.DOMAIN_PAUSED || state == libvirt.DOMAIN_PMSUSPENDED {
			ips := domainIPs(d, name)
			if len(ips) > 0 {
				primaryIP = ips[0]
				ip = strings.Join(ips, ", ")
			}
		}
		result = append(result, vmInfo{
			Name:      name,
			State:     formatState(state),
			MemoryMiB: mem,
			VCPU:      vcpu,
			VolumeGB:  volGB,
			IP:        ip,
			PrimaryIP: primaryIP,
		})
	}
	return result, nil
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
		//log.Printf("block info: %v", err)
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

func domainIPs(d libvirt.Domain, name string) []string {
	sources := []libvirt.DomainInterfaceAddressesSource{
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_ARP,
	}
	var ipv4 []string
	var ipv6 []string
	seen := make(map[string]struct{})
	var firstErr error

	for _, src := range sources {
		ifaces, err := d.ListAllInterfaceAddresses(src)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, iface := range ifaces {
			for _, addr := range iface.Addrs {
				if addr.Addr == "" {
					continue
				}
				if _, ok := seen[addr.Addr]; ok {
					continue
				}
				seen[addr.Addr] = struct{}{}
				switch addr.Type {
				case libvirt.IP_ADDR_TYPE_IPV4:
					ipv4 = append(ipv4, addr.Addr)
				case libvirt.IP_ADDR_TYPE_IPV6:
					ipv6 = append(ipv6, addr.Addr)
				default:
					ipv4 = append(ipv4, addr.Addr)
				}
			}
		}
	}

	if len(ipv4) == 0 && len(ipv6) == 0 && firstErr != nil {
		log.Printf("domain ip addresses %s: %v", name, firstErr)
	}

	return append(ipv4, ipv6...)
}

func formatState(state libvirt.DomainState) string {
	switch state {
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

type SingletonWorker struct {
	ticker *time.Ticker
	ctx    context.Context
	cancel context.CancelFunc
	vms    []vmInfo
}

func (s *SingletonWorker) GetVMs() []vmInfo {
	return s.vms
}

func (s *SingletonWorker) GetIpOfVm(vmName string) (string, error) {
	for _, vm := range s.vms {
		if vm.Name == vmName {
			return vm.PrimaryIP, nil
		}
	}
	return "", fmt.Errorf("VM %s not found", vmName)
}

var (
	instance *SingletonWorker
	once     sync.Once
)

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

	for {
		select {
		case <-s.ticker.C:
			s.doWork()
		case <-s.ctx.Done():
			log.Println("singleton worker stopped")
			return
		}
	}
}

func (s *SingletonWorker) doWork() {
	log.Println("doing work every 2 seconds")
	var err error
	s.vms, err = ListVMs("")
	if err != nil {
		log.Printf("singleton worker list vms: %v", err)
	}
}

func (s *SingletonWorker) Stop() {
	s.cancel()
	s.ticker.Stop()
}

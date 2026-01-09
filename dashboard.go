package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"rdptlsgateway/internal/virt"
)

const dashboardHTMLPath = "static/dashboard.html"

type dashboardVM struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	RDPHost   string `json:"rdpHost"`
	State     string `json:"state"`
	MemoryMiB int    `json:"memoryMiB"`
	VCPU      int    `json:"vcpu"`
	VolumeGB  int    `json:"volumeGB"`
}

type dashboardDataResponse struct {
	Filename string        `json:"filename"`
	VMs      []dashboardVM `json:"vms"`
	Error    string        `json:"error,omitempty"`
}

type dashboardActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func renderDashboardPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardHTML, err := fs.ReadFile(staticFiles, dashboardHTMLPath)
	if err != nil {
		log.Printf("render dashboard page: %v", err)
		http.Error(w, "Dashboard template unavailable.", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(dashboardHTML); err != nil {
		log.Printf("render dashboard page: %v", err)
	}
}

func listDashboardVMs() ([]dashboardVM, error) {
	vmList, err := virt.ListVMs("")
	if err != nil {
		return nil, err
	}
	rows := make([]dashboardVM, 0, len(vmList))
	for _, vm := range vmList {
		rdpHost := rdpTargetHost(vm.Name)
		rows = append(rows, dashboardVM{
			Name:      vm.Name,
			IP:        vm.IP,
			RDPHost:   rdpHost,
			State:     vm.State,
			MemoryMiB: vm.MemoryMiB,
			VCPU:      vm.VCPU,
			VolumeGB:  vm.VolumeGB,
		})
	}
	return rows, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

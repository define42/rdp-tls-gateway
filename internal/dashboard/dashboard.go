// Package dashboard contains dashboard page rendering helpers and
// data contracts used by the gateway API.
package dashboard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
	"strings"
)

// DashboardHTMLPath is the embedded dashboard HTML template location.
const DashboardHTMLPath = "static/dashboard.html"

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
)

// VM represents a single virtual machine row returned to the dashboard.
type VM struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	RDPConnect  string `json:"rdpConnect"`
	IP          string `json:"ip"`
	State       string `json:"state"`
	MemoryMiB   int    `json:"memoryMiB"`
	VCPU        int    `json:"vcpu"`
	VolumeGB    int    `json:"volumeGB"`
	TTYReady    bool   `json:"ttyReady"`
	VNCReady    bool   `json:"vncReady"`
}

// DataResponse is the API response for /api/dashboard/data.
type DataResponse struct {
	Filename string `json:"filename"`
	VMs      []VM   `json:"vms"`
	Error    string `json:"error,omitempty"`
}

// ActionResponse is the API response envelope used by dashboard actions.
type ActionResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RenderDashboardPage writes the dashboard HTML page to the HTTP response.
func RenderDashboardPage(w http.ResponseWriter, staticFiles fs.FS) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardHTML, err := fs.ReadFile(staticFiles, DashboardHTMLPath)
	if err != nil {
		log.Printf("render dashboard page: %v", err)
		http.Error(w, "Dashboard template unavailable.", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(dashboardHTML); err != nil {
		log.Printf("render dashboard page: %v", err)
	}
}

// GenerateRDP builds a base64-encoded RDP payload for the provided server/user pair.
func GenerateRDP(server, username string) string {
	lines := []string{
		fmt.Sprintf("full address:s:%s:443", server),
		fmt.Sprintf("username:s:%s", username),
		"prompt for credentials:i:1",
		"administrative session:i:1",
		"enablecredsspsupport:i:0",
	}

	rdp := strings.Join(lines, "\n") + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(rdp))

	return "data:application/x-rdp;base64," + encoded
}

// ListDashboardVMs returns VM rows visible to the given user.
func ListDashboardVMs(settings *config.SettingsType, user string) ([]VM, error) {
	vmList := virt.GetInstance().GetVMs(user)
	return buildDashboardRows(vmList, settings, user), nil
}

func buildDashboardRows(vmList []virt.VMInfo, settings *config.SettingsType, user string) []VM {
	rows := make([]VM, 0, len(vmList))
	for _, vm := range vmList {
		displayName := vm.Name
		if domain := strings.TrimSpace(settings.GetString(config.FRONT_DOMAIN)); domain != "" {
			displayName = vm.Name + "." + domain
		}
		rows = append(rows, VM{
			Name:        vm.Name,
			DisplayName: displayName,
			RDPConnect:  GenerateRDP(displayName, user),
			IP:          vm.IP,
			State:       vm.State,
			MemoryMiB:   vm.MemoryMiB,
			VCPU:        vm.VCPU,
			VolumeGB:    vm.VolumeGB,
			TTYReady:    vm.TTYReady,
			VNCReady:    vm.VNCReady,
		})
	}
	return rows
}

// WriteJSON serializes a payload as JSON with cache-control headers.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

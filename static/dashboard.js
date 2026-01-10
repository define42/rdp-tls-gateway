"use strict";
const DEFAULT_VM_ERROR = "Unable to load virtual machines right now.";
const AUTO_REFRESH_INTERVAL_MS = 10000;
const state = {
    vms: [],
    filename: "rdpgw.rdp",
    vmError: "",
    actionMessage: "",
    actionError: "",
    loading: true,
    busy: false,
};
let loadInFlight = false;
function isValidIPv4(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return false;
    }
    const parts = trimmed.split(".");
    if (parts.length !== 4) {
        return false;
    }
    return parts.every((part) => {
        if (!/^\d{1,3}$/.test(part)) {
            return false;
        }
        const num = Number(part);
        return num >= 0 && num <= 255;
    });
}
function isActiveState(state) {
    const normalized = state.trim().toLowerCase();
    return normalized === "running" || normalized === "paused" || normalized === "suspended";
}
function bootstrap() {
    const root = document.getElementById("app");
    if (!root) {
        return;
    }
    root.innerHTML = `
    <main class="card">
      <section class="vm-panel">
        <div class="vm-header">
          <h2>Available VMs</h2>
          <a class="logout-button" href="/logout">Logout</a>
        </div>
        <p class="vm-subtitle">Live inventory from libvirt.</p>
        <form class="vm-form" id="create-form">
          <div class="field">
            <label for="vm-name">New VM Name</label>
            <input id="vm-name" name="vm_name" autocomplete="off" pattern="[A-Za-z0-9_-]+" maxlength="64" title="Letters, numbers, '-' or '_' only" required>
          </div>
          <button id="create-button" type="submit">Create VM</button>
        </form>
        <div id="action-area" aria-live="polite"></div>
        <div id="vm-list"></div>
      </section>
    </main>
  `;
    const form = root.querySelector("#create-form");
    const input = root.querySelector("#vm-name");
    const createButton = root.querySelector("#create-button");
    const actionArea = root.querySelector("#action-area");
    const listArea = root.querySelector("#vm-list");
    if (!form || !input || !createButton || !actionArea || !listArea) {
        return;
    }
    const formEl = form;
    const inputEl = input;
    const createButtonEl = createButton;
    const actionAreaEl = actionArea;
    const listAreaEl = listArea;
    function renderAction() {
        actionAreaEl.innerHTML = "";
        if (state.actionError) {
            const error = document.createElement("p");
            error.className = "vm-error";
            error.textContent = state.actionError;
            actionAreaEl.appendChild(error);
            return;
        }
        if (state.actionMessage) {
            const message = document.createElement("p");
            message.className = "vm-success";
            message.textContent = state.actionMessage;
            actionAreaEl.appendChild(message);
        }
    }
    function renderVMList() {
        listAreaEl.innerHTML = "";
        if (state.loading) {
            const loading = document.createElement("p");
            loading.className = "vm-loading";
            loading.textContent = "Loading virtual machines...";
            listAreaEl.appendChild(loading);
            return;
        }
        if (state.vmError) {
            const error = document.createElement("p");
            error.className = "vm-error";
            error.textContent = state.vmError;
            listAreaEl.appendChild(error);
            return;
        }
        if (state.vms.length === 0) {
            const empty = document.createElement("p");
            empty.className = "vm-empty";
            empty.textContent = "No virtual machines found.";
            listAreaEl.appendChild(empty);
            return;
        }
        const wrap = document.createElement("div");
        wrap.className = "vm-table-wrap";
        const table = document.createElement("table");
        table.className = "vm-table";
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        const columns = [
            "Name",
            "IP Address",
            "State",
            "Memory",
            "vCPU",
            "Disk",
            "Actions",
        ];
        for (const label of columns) {
            const th = document.createElement("th");
            th.textContent = label;
            headRow.appendChild(th);
        }
        thead.appendChild(headRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        for (const vm of state.vms) {
            const row = document.createElement("tr");
            const rawName = vm.name || "";
            const displayName = vm.displayName || rawName;
            const nameCell = document.createElement("td");
            nameCell.className = "vm-name";
            if (vm.rdpConnect && displayName.trim() !== "") {
                const link = document.createElement("a");
                link.className = "vm-name-link";
                link.href = vm.rdpConnect;
                link.textContent = displayName;
                link.setAttribute("download", state.filename);
                nameCell.appendChild(link);
            }
            else {
                nameCell.textContent = displayName || "n/a";
            }
            row.appendChild(nameCell);
            const ipCell = document.createElement("td");
            ipCell.textContent = vm.ip || "n/a";
            row.appendChild(ipCell);
            const stateCell = document.createElement("td");
            stateCell.className = "vm-state";
            stateCell.textContent = vm.state || "n/a";
            row.appendChild(stateCell);
            const memoryCell = document.createElement("td");
            memoryCell.textContent = vm.memoryMiB ? `${vm.memoryMiB} MiB` : "n/a";
            row.appendChild(memoryCell);
            const vcpuCell = document.createElement("td");
            vcpuCell.textContent = vm.vcpu ? `${vm.vcpu}` : "n/a";
            row.appendChild(vcpuCell);
            const diskCell = document.createElement("td");
            diskCell.textContent = vm.volumeGB ? `${vm.volumeGB} GB` : "n/a";
            row.appendChild(diskCell);
            const hasIPv4 = vm.ip ? isValidIPv4(vm.ip) : false;
            const hasName = rawName.trim() !== "";
            const isActive = isActiveState(vm.state || "");
            const actionCell = document.createElement("td");
            const actions = document.createElement("div");
            actions.className = "vm-actions";
            const startButton = document.createElement("button");
            startButton.type = "button";
            startButton.className = "vm-power vm-start";
            startButton.textContent = "Start";
            startButton.disabled = state.busy || !hasName || isActive;
            startButton.addEventListener("click", () => {
                void startVM(rawName);
            });
            actions.appendChild(startButton);
            const restartButton = document.createElement("button");
            restartButton.type = "button";
            restartButton.className = "vm-power vm-restart";
            restartButton.textContent = "Restart";
            restartButton.disabled = state.busy || !hasName || !isActive;
            restartButton.addEventListener("click", () => {
                void restartVM(rawName);
            });
            actions.appendChild(restartButton);
            const shutdownButton = document.createElement("button");
            shutdownButton.type = "button";
            shutdownButton.className = "vm-power vm-shutdown";
            shutdownButton.textContent = "Shutdown";
            shutdownButton.disabled = state.busy || !hasName || !isActive;
            shutdownButton.addEventListener("click", () => {
                void shutdownVM(rawName);
            });
            actions.appendChild(shutdownButton);
            const removeButton = document.createElement("button");
            removeButton.type = "button";
            removeButton.className = "vm-remove";
            removeButton.textContent = "Remove";
            removeButton.disabled = state.busy || !hasName;
            removeButton.addEventListener("click", () => {
                void removeVM(rawName);
            });
            actions.appendChild(removeButton);
            actionCell.appendChild(actions);
            row.appendChild(actionCell);
            tbody.appendChild(row);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        listAreaEl.appendChild(wrap);
    }
    function setBusy(isBusy) {
        state.busy = isBusy;
        inputEl.disabled = isBusy;
        createButtonEl.disabled = isBusy;
        renderVMList();
    }
    function setActionError(message) {
        state.actionError = message;
        state.actionMessage = "";
        renderAction();
    }
    function setActionMessage(message) {
        state.actionMessage = message;
        state.actionError = "";
        renderAction();
    }
    function clearAction() {
        state.actionError = "";
        state.actionMessage = "";
        renderAction();
    }
    function applyInitialMessage() {
        const params = new URLSearchParams(window.location.search);
        if (params.has("removed")) {
            setActionMessage("VM removed.");
            params.delete("removed");
        }
        else if (params.has("created")) {
            setActionMessage("VM creation started.");
            params.delete("created");
        }
        if (params.toString() !== window.location.search.replace(/^\?/, "")) {
            const query = params.toString();
            const next = query ? `${window.location.pathname}?${query}` : window.location.pathname;
            window.history.replaceState({}, "", next);
        }
    }
    async function requestJSON(url, init = {}) {
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        const response = await fetch(url, {
            ...init,
            headers,
            credentials: "same-origin",
        });
        if (response.redirected) {
            const redirectedUrl = new URL(response.url);
            if (redirectedUrl.pathname === "/login") {
                window.location.assign("/login");
                return null;
            }
        }
        let payload = null;
        try {
            payload = await response.json();
        }
        catch {
            payload = null;
        }
        if (!response.ok) {
            const errorMessage = payload && typeof payload.error === "string"
                ? payload.error
                : "Request failed.";
            return { ok: false, error: errorMessage };
        }
        return { ok: true, data: payload };
    }
    async function loadVMs(options = {}) {
        var _a;
        if (loadInFlight) {
            return;
        }
        loadInFlight = true;
        const showLoading = (_a = options.showLoading) !== null && _a !== void 0 ? _a : state.vms.length === 0;
        if (showLoading) {
            state.loading = true;
            state.vmError = "";
            renderVMList();
        }
        try {
            const result = await requestJSON("/api/dashboard/data");
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                state.vmError = result.error || DEFAULT_VM_ERROR;
                return;
            }
            state.vms = result.data.vms || [];
            if (result.data.filename) {
                state.filename = result.data.filename;
            }
            if (result.data.error) {
                state.vmError = result.data.error;
            }
            else {
                state.vmError = "";
            }
        }
        finally {
            state.loading = false;
            renderVMList();
            loadInFlight = false;
        }
    }
    async function createVM(name) {
        if (state.busy) {
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({ vm_name: name });
            const result = await requestJSON("/api/dashboard", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: body.toString(),
            });
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                setActionError(result.error || "Failed to create VM.");
                return;
            }
            if (!result.data.ok) {
                setActionError(result.data.error || "Failed to create VM.");
                return;
            }
            setActionMessage(result.data.message || "VM creation started.");
            inputEl.value = "";
            await loadVMs();
        }
        finally {
            setBusy(false);
        }
    }
    async function actionVM(name, url, successMessage, failureMessage) {
        if (state.busy) {
            return;
        }
        clearAction();
        setBusy(true);
        try {
            const body = new URLSearchParams({ vm_name: name });
            const result = await requestJSON(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: body.toString(),
            });
            if (!result) {
                return;
            }
            if (!result.ok || !result.data) {
                setActionError(result.error || failureMessage);
                return;
            }
            if (!result.data.ok) {
                setActionError(result.data.error || failureMessage);
                return;
            }
            setActionMessage(result.data.message || successMessage);
            await loadVMs();
        }
        finally {
            setBusy(false);
        }
    }
    async function removeVM(name) {
        await actionVM(name, "/api/dashboard/remove", "VM removed.", "Failed to remove VM.");
    }
    async function startVM(name) {
        await actionVM(name, "/api/dashboard/start", "VM start requested.", "Failed to start VM.");
    }
    async function restartVM(name) {
        await actionVM(name, "/api/dashboard/restart", "VM restart requested.", "Failed to restart VM.");
    }
    async function shutdownVM(name) {
        await actionVM(name, "/api/dashboard/shutdown", "VM shutdown requested.", "Failed to shutdown VM.");
    }
    formEl.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!formEl.reportValidity()) {
            return;
        }
        void createVM(inputEl.value.trim());
    });
    applyInitialMessage();
    renderAction();
    renderVMList();
    void loadVMs();
    const refreshHandle = window.setInterval(() => {
        if (document.hidden || state.busy) {
            return;
        }
        void loadVMs({ showLoading: false });
    }, AUTO_REFRESH_INTERVAL_MS);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) {
            void loadVMs({ showLoading: false });
        }
    });
    window.addEventListener("beforeunload", () => {
        window.clearInterval(refreshHandle);
    });
}
bootstrap();

package tracer

import (
	"path/filepath"
	"strconv"
	"strings"
)

// Hard-denied processes must never receive TLS plaintext uprobes, even when --peer_ip
// scopes PID discovery to them. Hooking these can crash or destabilize the node.
var plaintextHardDeniedBasenames = map[string]struct{}{
	"cluster-version-operator":     {},
	"crio":                         {},
	"hyperkube":                    {},
	"kube-apiserver":               {},
	"kube-controller-manager":      {},
	"kube-multus":                  {},
	"kube-proxy":                   {},
	"kube-rbac-proxy":              {},
	"kube-scheduler":               {},
	"kubelet":                      {},
	"konnectivity-agent":           {},
	"coredns":                      {},
	"machine-config-daemon":        {},
	"multus":                       {},
	"openshift-apiserver":          {},
	"openshift-controller-manager": {},
	"openshift-kube-apiserver":     {},
	"ovnkube":                      {},
	"ovnkube-node":                 {},
}

var plaintextHardDeniedComms = map[string]struct{}{
	"coredns":         {},
	"crio":            {},
	"kube-multus":     {},
	"kube-rbac-proxy": {},
	"kubelet":         {},
	"multus":          {},
	"ovnkube":         {},
}

var plaintextHardDeniedCommPrefixes = []string{
	"konnectivity",
	"ovnkube",
	"multus",
}

// Soft-excluded processes are skipped during broad auto-discovery but may be hooked
// when peer_ip / peer_cidr scopes PID discovery to them (e.g. openshift-console).
var plaintextSoftExcludedBasenames = map[string]struct{}{
	"console":                {},
	"kubectl":                {},
	"network-metrics-daemon": {},
}

var plaintextSoftExcludedComms = map[string]struct{}{
	"console": {},
}

var plaintextSoftExcludedCommPrefixes = []string{
	"network-metrics",
	"openshift-con",
}

var plaintextExcludedPathPrefixes = []string{
	"/etc/kubernetes/",
	"/var/lib/kubelet/",
	"/usr/lib/kubelet/",
	"/usr/libexec/kubelet/",
}

func commMatches(comm string, exact map[string]struct{}, prefixes []string) bool {
	if comm != "" {
		if _, ok := exact[comm]; ok {
			return true
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(comm, prefix) {
				return true
			}
		}
	}
	return false
}

func basenameMatches(resolvedPath string, names map[string]struct{}) bool {
	resolvedPath = normalizeExePath(resolvedPath)
	base := filepath.Base(resolvedPath)
	_, ok := names[base]
	return ok
}

func isPlaintextCaptureHardDenied(resolvedPath, comm string) bool {
	if commMatches(comm, plaintextHardDeniedComms, plaintextHardDeniedCommPrefixes) {
		return true
	}
	if basenameMatches(resolvedPath, plaintextHardDeniedBasenames) {
		return true
	}

	resolvedPath = normalizeExePath(resolvedPath)
	for _, prefix := range plaintextExcludedPathPrefixes {
		if strings.HasPrefix(resolvedPath, prefix) {
			return true
		}
	}

	base := filepath.Base(resolvedPath)
	if strings.HasPrefix(resolvedPath, "/usr/bin/") {
		if strings.HasPrefix(base, "kube-") || strings.HasPrefix(base, "openshift-") {
			return true
		}
	}

	return false
}

func isPlaintextCaptureSoftExcluded(resolvedPath, comm string) bool {
	if commMatches(comm, plaintextSoftExcludedComms, plaintextSoftExcludedCommPrefixes) {
		return true
	}
	return basenameMatches(resolvedPath, plaintextSoftExcludedBasenames)
}

func isPlaintextCaptureExcluded(resolvedPath, comm string) bool {
	return isPlaintextCaptureHardDenied(resolvedPath, comm) ||
		isPlaintextCaptureSoftExcluded(resolvedPath, comm)
}

func isPlaintextCaptureExcludedPID(pidStr string, scope *PlaintextScope) bool {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return true
	}
	exePath := filepath.Join(procRootDir, pidStr, "exe")
	resolved, comm := resolveProcExe(pidStr, exePath)

	if scope != nil && scope.PIDScoped(pid) {
		// peer_ip / peer_cidr scoped this PID; allow soft-excluded workloads (console, …).
		return isPlaintextCaptureHardDenied(resolved, comm)
	}
	return isPlaintextCaptureExcluded(resolved, comm)
}

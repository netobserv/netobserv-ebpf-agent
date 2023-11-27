package utils

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

var (
	getCurrentKernelVersion = currentKernelVersion
	log                     = logrus.WithField("component", "utils")
)

// GetSocket returns socket string in the correct format based on address family
func GetSocket(hostIP string, hostPort int) string {
	socket := fmt.Sprintf("%s:%d", hostIP, hostPort)
	ipAddr := net.ParseIP(hostIP)
	if ipAddr != nil && ipAddr.To4() == nil {
		socket = fmt.Sprintf("[%s]:%d", hostIP, hostPort)
	}
	return socket
}

func IskernelOlderthan514() bool {
	kernelVersion514, err := kernelVersionFromReleaseString("5.14.0")
	if err != nil {
		log.Warnf("failed to get kernel version from release string: %v", err)
		return false
	}
	currentVersion, err := getCurrentKernelVersion()
	if err != nil {
		log.Warnf("failed to get current kernel version: %v", err)
		return false
	}
	if currentVersion < kernelVersion514 {
		log.Infof("older kernel version not all hooks will be supported")
		return true
	}
	return false
}

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+).(\d+).*$`)

// kernelVersionFromReleaseString converts a release string with format
// 4.4.2[-1] to a kernel version number in LINUX_VERSION_CODE format.
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func kernelVersionFromReleaseString(releaseString string) (uint32, error) {
	versionParts := versionRegex.FindStringSubmatch(releaseString)
	if len(versionParts) != 4 {
		return 0, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString)
	}
	major, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return 0, err
	}

	minor, err := strconv.Atoi(versionParts[2])
	if err != nil {
		return 0, err
	}

	patch, err := strconv.Atoi(versionParts[3])
	if err != nil {
		return 0, err
	}
	out := major*256*256 + minor*256 + patch
	return uint32(out), nil
}

func currentKernelVersion() (uint32, error) {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return 0, err
	}
	releaseString := strings.Trim(utsnameStr(buf.Release[:]), "\x00")
	return kernelVersionFromReleaseString(releaseString)
}

func utsnameStr[T int8 | uint8](in []T) string {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}

func GetInterfaceName(ifIndex uint32) string {
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return ""
	}
	return iface.Name
}

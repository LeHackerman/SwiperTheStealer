package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel represents logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// Logger provides structured logging functionality
type Logger struct {
	level      LogLevel
	logger     *log.Logger
	timeFormat string
}

// NewLogger creates a new logger instance
func NewLogger(level string) *Logger {
	var logLevel LogLevel
	switch strings.ToLower(level) {
	case "debug":
		logLevel = DEBUG
	case "info":
		logLevel = INFO
	case "warn", "warning":
		logLevel = WARN
	case "error":
		logLevel = ERROR
	case "fatal":
		logLevel = FATAL
	default:
		logLevel = INFO
	}

	return &Logger{
		level:      logLevel,
		logger:     log.New(os.Stdout, "", 0),
		timeFormat: "2006-01-02 15:04:05",
	}
}

// formatMessage formats log messages with timestamp and level
func (l *Logger) formatMessage(level LogLevel, format string, args ...interface{}) string {
	levelStr := map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
		FATAL: "FATAL",
	}[level]

	timestamp := time.Now().Format(l.timeFormat)
	message := fmt.Sprintf(format, args...)
	return fmt.Sprintf("[%s] [%s] %s", timestamp, levelStr, message)
}

// log outputs the message if it meets the minimum level requirement
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level >= l.level {
		l.logger.Println(l.formatMessage(level, format, args...))
	}
}

// Debug logs debug messages
func (l *Logger) Debug(msg string) {
	l.log(DEBUG, msg)
}

// Debugf logs formatted debug messages
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs info messages
func (l *Logger) Info(msg string) {
	l.log(INFO, msg)
}

// Infof logs formatted info messages
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs warning messages
func (l *Logger) Warn(msg string) {
	l.log(WARN, msg)
}

// Warnf logs formatted warning messages
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs error messages
func (l *Logger) Error(msg string) {
	l.log(ERROR, msg)
}

// Errorf logs formatted error messages
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs fatal messages and exits
func (l *Logger) Fatal(msg string) {
	l.log(FATAL, msg)
	os.Exit(1)
}

// Fatalf logs formatted fatal messages and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

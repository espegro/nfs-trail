package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"debug", DEBUG},
		{"DEBUG", DEBUG},
		{"info", INFO},
		{"INFO", INFO},
		{"warn", WARN},
		{"warning", WARN},
		{"WARN", WARN},
		{"error", ERROR},
		{"ERROR", ERROR},
		{"invalid", INFO}, // Default
		{"", INFO},        // Default
	}

	for _, tt := range tests {
		result := ParseLevel(tt.input)
		if result != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
	}

	for _, tt := range tests {
		result := tt.level.String()
		if result != tt.expected {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, result, tt.expected)
		}
	}
}

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  INFO,
		logger: newTestLogger(&buf),
	}

	// Debug should not be logged (level is INFO)
	logger.Debug("debug message")
	if buf.Len() > 0 {
		t.Error("Debug message was logged when level is INFO")
	}

	// Info should be logged
	buf.Reset()
	logger.Info("info message")
	if !strings.Contains(buf.String(), "[INFO]") {
		t.Error("Info message was not logged")
	}
	if !strings.Contains(buf.String(), "info message") {
		t.Error("Info message content missing")
	}

	// Warn should be logged
	buf.Reset()
	logger.Warn("warn message")
	if !strings.Contains(buf.String(), "[WARN]") {
		t.Error("Warn message was not logged")
	}

	// Error should be logged
	buf.Reset()
	logger.Error("error message")
	if !strings.Contains(buf.String(), "[ERROR]") {
		t.Error("Error message was not logged")
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  INFO,
		logger: newTestLogger(&buf),
	}

	// Debug should not be logged at INFO level
	logger.Debug("debug1")
	if buf.Len() > 0 {
		t.Error("Debug was logged at INFO level")
	}

	// Change to DEBUG level
	logger.SetLevel(DEBUG)

	// Now debug should be logged
	buf.Reset()
	logger.Debug("debug2")
	if !strings.Contains(buf.String(), "[DEBUG]") {
		t.Error("Debug message was not logged at DEBUG level")
	}

	// Change to ERROR level
	logger.SetLevel(ERROR)

	// Info and Warn should not be logged
	buf.Reset()
	logger.Info("info3")
	logger.Warn("warn3")
	if buf.Len() > 0 {
		t.Error("Info/Warn were logged at ERROR level")
	}

	// Error should be logged
	buf.Reset()
	logger.Error("error3")
	if !strings.Contains(buf.String(), "[ERROR]") {
		t.Error("Error message was not logged at ERROR level")
	}
}

func TestLoggerFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  INFO,
		logger: newTestLogger(&buf),
	}

	logger.Info("test %d %s", 123, "abc")
	output := buf.String()

	if !strings.Contains(output, "test 123 abc") {
		t.Errorf("Message not formatted correctly: %q", output)
	}
}

func TestGetLogger(t *testing.T) {
	logger1 := GetLogger()
	logger2 := GetLogger()

	if logger1 != logger2 {
		t.Error("GetLogger should return the same instance")
	}

	if logger1 == nil {
		t.Error("GetLogger returned nil")
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	var buf bytes.Buffer
	// Replace default logger for testing
	defaultLogger = &Logger{
		level:  DEBUG,
		logger: newTestLogger(&buf),
	}

	Debug("debug msg")
	if !strings.Contains(buf.String(), "[DEBUG]") {
		t.Error("Package-level Debug() didn't work")
	}

	buf.Reset()
	Info("info msg")
	if !strings.Contains(buf.String(), "[INFO]") {
		t.Error("Package-level Info() didn't work")
	}

	buf.Reset()
	Warn("warn msg")
	if !strings.Contains(buf.String(), "[WARN]") {
		t.Error("Package-level Warn() didn't work")
	}

	buf.Reset()
	Error("error msg")
	if !strings.Contains(buf.String(), "[ERROR]") {
		t.Error("Package-level Error() didn't work")
	}
}

func TestSetLevelPackageLevel(t *testing.T) {
	var buf bytes.Buffer
	defaultLogger = &Logger{
		level:  INFO,
		logger: newTestLogger(&buf),
	}

	// Debug should not be logged
	Debug("debug1")
	if buf.Len() > 0 {
		t.Error("Debug was logged at INFO level")
	}

	// Set to DEBUG via package function
	SetLevel(DEBUG)

	buf.Reset()
	Debug("debug2")
	if !strings.Contains(buf.String(), "[DEBUG]") {
		t.Error("Debug not logged after SetLevel(DEBUG)")
	}
}

// Helper to create test logger without timestamps
func newTestLogger(w *bytes.Buffer) *log.Logger {
	return log.New(w, "", 0) // No prefix, no flags
}

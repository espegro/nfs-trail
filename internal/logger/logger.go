package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// LogLevel represents logging severity
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of a log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a log level string
func ParseLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// Logger is a leveled logger
type Logger struct {
	level  LogLevel
	logger *log.Logger
	mu     sync.Mutex
}

var (
	// Default logger instance
	defaultLogger *Logger
	once          sync.Once
)

// Init initializes the default logger
func Init(level string, output string) error {
	var writer io.Writer

	switch output {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// Assume it's a file path
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("opening log file: %w", err)
		}
		writer = f
	}

	defaultLogger = &Logger{
		level:  ParseLevel(level),
		logger: log.New(writer, "", log.LstdFlags),
	}

	return nil
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	once.Do(func() {
		if defaultLogger == nil {
			// Initialize with defaults if not already initialized
			defaultLogger = &Logger{
				level:  INFO,
				logger: log.New(os.Stdout, "", log.LstdFlags),
			}
		}
	})
	return defaultLogger
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// log logs a message at the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.GetLevel() {
		return
	}

	prefix := fmt.Sprintf("[%s] ", level.String())
	msg := fmt.Sprintf(format, args...)
	l.logger.Print(prefix + msg)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Package-level convenience functions

// Debug logs a debug message using the default logger
func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

// Info logs an info message using the default logger
func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

// Warn logs a warning message using the default logger
func Warn(format string, args ...interface{}) {
	GetLogger().Warn(format, args...)
}

// Error logs an error message using the default logger
func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

// SetLevel sets the logging level on the default logger
func SetLevel(level LogLevel) {
	GetLogger().SetLevel(level)
}

// Package rndc provides a logging system with multiple log levels and contextual information.
// It supports critical, error, warning, info, and debug log levels with configurable output.
package rndc

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// Level represents a log level.
// Log levels are ordered from most to least verbose: Debug, Info, Warn, Error, Critical.
type Level uint32

const (
	// CriticalLevel represents a critical error that may cause the application to exit.
	CriticalLevel Level = iota
	// ErrorLevel represents an error that may cause a function to fail.
	ErrorLevel
	// WarnLevel represents a warning that may indicate a potential problem.
	WarnLevel
	// InfoLevel represents general information about the application's operation.
	InfoLevel
	// DebugLevel represents detailed information useful for debugging.
	DebugLevel
)

// String returns the string representation of a Level.
func (level Level) String() string {
	switch level {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warning"
	case ErrorLevel:
		return "error"
	case CriticalLevel:
		return "critical"
	}

	return "unknown"
}

// StringToLevel converts a string to a Level.
// If the string does not match any known level, it returns InfoLevel.
// Valid strings are: "critical", "error", "warn", "warning", "debug", "info".
func StringToLevel(level string) Level {
	switch level {
	case "critical":
		return CriticalLevel
	case "error":
		return ErrorLevel
	case "warn", "warning":
		return WarnLevel
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	}
	return InfoLevel
}

var logger = NewLogger().WithDepth(4)

// Info logs a message at the info level.
func Info(ctx context.Context, format string, v ...interface{}) {
	logger.Info(ctx, format, v...)
}

// Debug logs a message at the debug level.
func Debug(ctx context.Context, format string, v ...interface{}) {
	logger.Debug(ctx, format, v...)
}

// Warn logs a message at the warning level.
func Warn(ctx context.Context, format string, v ...interface{}) {
	logger.Warn(ctx, format, v...)
}

// Error logs a message at the error level.
func Error(ctx context.Context, format string, v ...interface{}) {
	logger.Error(ctx, format, v...)
}

// Critical logs a message at the critical level.
func Critical(ctx context.Context, format string, v ...interface{}) {
	logger.Critical(ctx, format, v...)
}

// SetOutput sets the output writer for the default logger.
func SetOutput(output io.Writer) {
	logger.SetOutput(output)
}

var globalLogLevel uint32 = uint32(InfoLevel)

// SetLevelByString sets the log level for the default logger using a string.
// Valid strings are: "critical", "error", "warn", "warning", "debug", "info".
func SetLevelByString(level string) {
	logger.SetLevelByString(level)
	atomic.StoreUint32(&globalLogLevel, uint32(StringToLevel(level)))
}

// NewLogger creates a new Logger instance with default settings.
// The default level is InfoLevel, output is os.Stdout, and depth is 3.
func NewLogger() *Logger {
	return &Logger{
		Level:  Level(atomic.LoadUint32(&globalLogLevel)),
		output: os.Stdout,
		depth:  3,
	}
}

// Logger represents a logger with configurable level, output, and formatting options.
type Logger struct {
	// Level is the minimum level of messages that will be logged.
	Level Level
	// output is the writer where log messages are written.
	output io.Writer
	// hideCallstack determines whether to include file and line information in log messages.
	hideCallstack bool
	// depth is the stack depth used to determine the file and line number for log messages.
	depth int
}

// level returns the current log level of the logger.
func (logger *Logger) level() Level {
	return Level(atomic.LoadUint32((*uint32)(&logger.Level)))
}

// SetLevel sets the minimum level of messages that will be logged.
func (logger *Logger) SetLevel(level Level) {
	atomic.StoreUint32((*uint32)(&logger.Level), uint32(level))
}

// SetLevelByString sets the minimum level of messages that will be logged using a string.
// Valid strings are: "critical", "error", "warn", "warning", "debug", "info".
func (logger *Logger) SetLevelByString(level string) {
	logger.SetLevel(StringToLevel(level))
}

var replacer = strings.NewReplacer("\r", "\\r", "\n", "\\n")

// formatOutput formats a log message with timestamp, level, and optional file/line information.
func (logger *Logger) formatOutput(ctx context.Context, level Level, output string) string {
	now := time.Now().Format("2006-01-02 15:04:05.99999")

	output = replacer.Replace(output)

	var suffix string
	if logger.hideCallstack {
		return fmt.Sprintf("%-25s -%s- %s%s",
			now, strings.ToUpper(level.String()), output, suffix)
	} else {
		_, file, line, ok := runtime.Caller(logger.depth)
		if !ok {
			file = "???"
			line = 0
		}

		// short file name
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}

		return fmt.Sprintf("%-25s -%s- %s (%s:%d)%s",
			now, strings.ToUpper(level.String()), output, file, line, suffix)
	}
}

// logf logs a formatted message if the logger's level is greater than or equal to the specified level.
func (logger *Logger) logf(ctx context.Context, level Level, format string, args ...interface{}) {
	if logger.level() < level {
		return
	}
	fmt.Fprintln(logger.output, logger.formatOutput(ctx, level, fmt.Sprintf(format, args...)))
}

// Debug logs a message at the debug level.
func (logger *Logger) Debug(ctx context.Context, format string, args ...interface{}) {
	logger.logf(ctx, DebugLevel, format, args...)
}

// Info logs a message at the info level.
func (logger *Logger) Info(ctx context.Context, format string, args ...interface{}) {
	logger.logf(ctx, InfoLevel, format, args...)
}

// Warn logs a message at the warning level.
func (logger *Logger) Warn(ctx context.Context, format string, args ...interface{}) {
	logger.logf(ctx, WarnLevel, format, args...)
}

// Error logs a message at the error level.
func (logger *Logger) Error(ctx context.Context, format string, args ...interface{}) {
	logger.logf(ctx, ErrorLevel, format, args...)
}

// Critical logs a message at the critical level.
func (logger *Logger) Critical(ctx context.Context, format string, args ...interface{}) {
	logger.logf(ctx, CriticalLevel, format, args...)
}

// SetOutput sets the output writer for the logger and returns the logger.
func (logger *Logger) SetOutput(output io.Writer) *Logger {
	logger.output = output
	return logger
}

// HideCallstack configures the logger to hide file and line information in log messages.
// Returns the logger for method chaining.
func (logger *Logger) HideCallstack() *Logger {
	logger.hideCallstack = true
	return logger
}

// WithDepth sets the stack depth used to determine the file and line number for log messages.
// Returns the logger for method chaining.
func (logger *Logger) WithDepth(depth int) *Logger {
	logger.depth = depth
	return logger
}

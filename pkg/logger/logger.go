// Package logger provides structured logging utilities with field support
// for better debugging and monitoring of webhook sprinkler operations.
package logger

import (
	"fmt"
	"log"
	"strings"
)

// Fields represents structured log fields.
type Fields map[string]interface{}

// WithFields adds structured context to log messages.
func WithFields(fields Fields, format string, args ...interface{}) {
	var parts []string
	for k, v := range fields {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}

	msg := fmt.Sprintf(format, args...)
	if len(parts) > 0 {
		log.Printf("%s [%s]", msg, strings.Join(parts, " "))
	} else {
		log.Print(msg)
	}
}

// Info logs an info message with optional fields.
func Info(msg string, fields Fields) {
	WithFields(fields, "%s", msg)
}

// Error logs an error message with optional fields.
func Error(msg string, err error, fields Fields) {
	if fields == nil {
		fields = Fields{}
	}
	fields["error"] = err.Error()
	WithFields(fields, "ERROR: %s", msg)
}

// Warn logs a warning message with optional fields.
func Warn(msg string, fields Fields) {
	WithFields(fields, "WARNING: %s", msg)
}

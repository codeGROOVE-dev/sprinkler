// Package logger provides structured logging utilities with field support
// for better debugging and monitoring of webhook sprinkler operations.
package logger

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

// Fields represents structured log fields.
type Fields map[string]any

// WithFieldsf adds structured context to log messages with printf-style formatting.
func WithFieldsf(fields Fields, format string, args ...any) {
	// Sort keys for consistent output
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
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
	WithFieldsf(fields, "%s", msg)
}

// Error logs an error message with optional fields.
func Error(msg string, err error, fields Fields) {
	if fields == nil {
		fields = Fields{}
	}
	fields["error"] = err.Error()
	WithFieldsf(fields, "ERROR: %s", msg)
}

// Warn logs a warning message with optional fields.
func Warn(msg string, fields Fields) {
	WithFieldsf(fields, "WARNING: %s", msg)
}

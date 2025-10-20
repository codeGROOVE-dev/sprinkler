// Package logger provides structured logging using slog with hostname tracking
// and short source file paths for better debugging across multiple instances.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Fields represents structured log fields.
type Fields map[string]any

var (
	// defaultLogger is the global logger instance.
	defaultLogger *slog.Logger
	// hostname is cached on init for performance.
	hostname string
)

func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Initialize with default text handler
	defaultLogger = New(os.Stderr)
}

// New creates a new slog logger with hostname and short source paths.
func New(w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Shorten source file paths to just basename:line
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					source.File = filepath.Base(source.File)
					// Remove function name to keep it concise
					source.Function = ""
				}
			}
			return a
		},
	}

	handler := slog.NewTextHandler(w, opts)
	logger := slog.New(handler)

	// Add hostname to all log messages
	return logger.With("instance", hostname)
}

// SetDefault sets the default logger.
func SetDefault(l *slog.Logger) {
	defaultLogger = l
}

// SetLogger sets the default logger (alias for SetDefault).
func SetLogger(l *slog.Logger) {
	defaultLogger = l
}

// Default returns the default logger.
func Default() *slog.Logger {
	return defaultLogger
}

// Hostname returns the cached hostname.
func Hostname() string {
	return hostname
}

// Info logs an info message with optional fields.
func Info(msg string, fields Fields) {
	defaultLogger.LogAttrs(context.Background(), slog.LevelInfo, msg, attrsFromFields(fields)...)
}

// Warn logs a warning message with optional fields.
func Warn(msg string, fields Fields) {
	defaultLogger.LogAttrs(context.Background(), slog.LevelWarn, msg, attrsFromFields(fields)...)
}

// Error logs an error message with optional fields.
func Error(msg string, err error, fields Fields) {
	if fields == nil {
		fields = Fields{}
	}
	fields["error"] = err.Error()
	defaultLogger.LogAttrs(context.Background(), slog.LevelError, msg, attrsFromFields(fields)...)
}

// Debug logs a debug message with optional fields.
func Debug(msg string, fields Fields) {
	defaultLogger.LogAttrs(context.Background(), slog.LevelDebug, msg, attrsFromFields(fields)...)
}

// attrsFromFields converts Fields to slog.Attr slice.
func attrsFromFields(fields Fields) []slog.Attr {
	if fields == nil {
		return nil
	}
	attrs := make([]slog.Attr, 0, len(fields))
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	return attrs
}

// LogAt logs a message at the specified level with source information.
// This is useful when you want to override the default source location.
func LogAt(level slog.Level, skip int, msg string, fields Fields) {
	var pcs [1]uintptr
	runtime.Callers(skip+2, pcs[:])
	r := slog.NewRecord(
		time.Now(),
		level,
		msg,
		pcs[0],
	)
	r.AddAttrs(attrsFromFields(fields)...)
	_ = defaultLogger.Handler().Handle(context.Background(), r) //nolint:errcheck // Best effort logging
}

// WithFieldsf provides backward compatibility for tests.
// Deprecated: Use Info/Warn/Error with Fields instead.
func WithFieldsf(fields Fields, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	Info(msg, fields)
}

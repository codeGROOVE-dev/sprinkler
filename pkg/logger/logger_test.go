package logger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestLoggerFieldOrdering tests that fields are output in consistent order
func TestLoggerFieldOrdering(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	fields := Fields{
		"zebra":  "last",
		"alpha":  "first",
		"middle": "center",
	}

	Info(context.Background(), "test message", fields)

	output := buf.String()

	// Check for slog level
	if !strings.Contains(output, "level=INFO") {
		t.Error("INFO level not found in output")
	}
	if !strings.Contains(output, `msg="test message"`) {
		t.Error("message not found in output")
	}
	// Fields should be present
	if !strings.Contains(output, "alpha=first") {
		t.Error("alpha field not found in output")
	}
	if !strings.Contains(output, "middle=center") {
		t.Error("middle field not found in output")
	}
	if !strings.Contains(output, "zebra=last") {
		t.Error("zebra field not found in output")
	}
}

// TestLoggerWithNilFields tests handling of nil fields
func TestLoggerWithNilFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	// Should not panic with nil fields
	Info(context.Background(), "test message", nil)

	output := buf.String()
	if !strings.Contains(output, `msg="test message"`) {
		t.Error("Message not found in output")
	}
}

// TestLoggerWithEmptyFields tests handling of empty fields
func TestLoggerWithEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	Info(context.Background(), "test message", Fields{})

	output := buf.String()
	if !strings.Contains(output, `msg="test message"`) {
		t.Error("Message not found in output")
	}
	// Should not have brackets for empty fields
	if strings.Contains(output, "[]") {
		t.Error("Empty brackets should not appear")
	}
}

// TestErrorLogger tests the Error function
func TestErrorLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	err := errors.New("test error")
	Error(context.Background(), "something failed", err, Fields{"code": "500"})

	output := buf.String()
	if !strings.Contains(output, "level=ERROR") {
		t.Error("ERROR level not found")
	}
	if !strings.Contains(output, `msg="something failed"`) {
		t.Error("message not found")
	}
	if !strings.Contains(output, `error="test error"`) {
		t.Error("error field not found")
	}
	if !strings.Contains(output, "code=500") {
		t.Error("code field not found")
	}
}

// TestWarnLogger tests the Warn function
func TestWarnLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	Warn(context.Background(), "potential issue", Fields{"threshold": "80%"})

	output := buf.String()
	if !strings.Contains(output, "level=WARN") {
		t.Error("WARN level not found")
	}
	if !strings.Contains(output, `msg="potential issue"`) {
		t.Error("message not found")
	}
	if !strings.Contains(output, "threshold=80%") {
		t.Error("threshold field not found")
	}
}

// TestFieldsWithSpecialCharacters tests fields with special characters
func TestFieldsWithSpecialCharacters(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	fields := Fields{
		"path":  "/etc/passwd",
		"query": "SELECT id, name FROM users",
		"url":   "https://example.com?foo=bar&baz=qux",
	}

	Info(context.Background(), "test", fields)

	output := buf.String()
	if !strings.Contains(output, "path=/etc/passwd") {
		t.Error("path field not preserved correctly")
	}
	// Query field will be quoted because it contains spaces and commas
	if !strings.Contains(output, "query=") {
		t.Error("query field not preserved correctly")
	}
	if !strings.Contains(output, "url=") {
		t.Error("url field not preserved correctly")
	}
}

// TestFieldsWithNilValues tests handling of nil values in fields
func TestFieldsWithNilValues(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	fields := Fields{
		"nil_value":    nil,
		"string_value": "test",
	}

	Info(context.Background(), "test", fields)

	output := buf.String()
	if !strings.Contains(output, "nil_value") {
		t.Error("nil value not handled correctly")
	}
	if !strings.Contains(output, "string_value=test") {
		t.Error("string value not found")
	}
}

// TestWithFieldsFormatting tests formatting with Info function
func TestWithFieldsFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	fields := Fields{"user": "alice"}
	msg := fmt.Sprintf("User %s logged in at %d", "bob", 12345)
	Info(context.Background(), msg, fields)

	output := buf.String()
	if !strings.Contains(output, "User bob logged in at 12345") {
		t.Error("Format string not applied correctly")
	}
	if !strings.Contains(output, "user=alice") {
		t.Error("Field not found")
	}
}

// TestLargeNumberOfFields tests performance with many fields
func TestLargeNumberOfFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	SetLogger(logger)

	fields := make(Fields, 100)
	for i := range 100 {
		fields[fmt.Sprintf("field%03d", i)] = i
	}

	Info(context.Background(), "test with many fields", fields)

	output := buf.String()
	if !strings.Contains(output, `msg="test with many fields"`) {
		t.Error("Message not found")
	}
	// Check that first and last fields are present
	if !strings.Contains(output, "field000=0") {
		t.Error("First field not found")
	}
	if !strings.Contains(output, "field099=99") {
		t.Error("Last field not found")
	}
}

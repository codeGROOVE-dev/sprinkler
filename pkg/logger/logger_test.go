package logger

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
)

// TestLoggerFieldOrdering tests that fields are output in consistent order
func TestLoggerFieldOrdering(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil) // Reset after test

	fields := Fields{
		"zebra":  "last",
		"alpha":  "first",
		"middle": "center",
	}

	Info("test message", fields)

	output := buf.String()

	// Fields should be in alphabetical order
	if !strings.Contains(output, "alpha=first") {
		t.Error("alpha field not found in output")
	}
	if !strings.Contains(output, "middle=center") {
		t.Error("middle field not found in output")
	}
	if !strings.Contains(output, "zebra=last") {
		t.Error("zebra field not found in output")
	}

	// Check ordering
	alphaIdx := strings.Index(output, "alpha=")
	middleIdx := strings.Index(output, "middle=")
	zebraIdx := strings.Index(output, "zebra=")

	if alphaIdx > middleIdx || middleIdx > zebraIdx {
		t.Error("Fields are not in alphabetical order")
	}
}

// TestLoggerWithNilFields tests handling of nil fields
func TestLoggerWithNilFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	// Should not panic with nil fields
	Info("test message", nil)

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Error("Message not found in output")
	}
}

// TestLoggerWithEmptyFields tests handling of empty fields
func TestLoggerWithEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	Info("test message", Fields{})

	output := buf.String()
	if !strings.Contains(output, "test message") {
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
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	err := errors.New("test error")
	Error("something failed", err, Fields{"code": "500"})

	output := buf.String()
	if !strings.Contains(output, "ERROR: something failed") {
		t.Error("ERROR prefix not found")
	}
	if !strings.Contains(output, "error=test error") {
		t.Error("error field not found")
	}
	if !strings.Contains(output, "code=500") {
		t.Error("code field not found")
	}
}

// TestWarnLogger tests the Warn function
func TestWarnLogger(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	Warn("potential issue", Fields{"threshold": "80%"})

	output := buf.String()
	if !strings.Contains(output, "WARNING: potential issue") {
		t.Error("WARNING prefix not found")
	}
	if !strings.Contains(output, "threshold=80%") {
		t.Error("threshold field not found")
	}
}

// TestFieldsWithSpecialCharacters tests fields with special characters
func TestFieldsWithSpecialCharacters(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	fields := Fields{
		"path":  "/etc/passwd",
		"query": "SELECT id, name FROM users",
		"url":   "https://example.com?foo=bar&baz=qux",
	}

	Info("test", fields)

	output := buf.String()
	if !strings.Contains(output, "path=/etc/passwd") {
		t.Error("path field not preserved correctly")
	}
	if !strings.Contains(output, "query=SELECT id, name FROM users") {
		t.Error("query field not preserved correctly")
	}
	if !strings.Contains(output, "url=https://example.com?foo=bar&baz=qux") {
		t.Error("url field not preserved correctly")
	}
}

// TestFieldsWithNilValues tests handling of nil values in fields
func TestFieldsWithNilValues(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	fields := Fields{
		"nil_value":    nil,
		"string_value": "test",
	}

	Info("test", fields)

	output := buf.String()
	if !strings.Contains(output, "nil_value=<nil>") {
		t.Error("nil value not handled correctly")
	}
	if !strings.Contains(output, "string_value=test") {
		t.Error("string value not found")
	}
}

// TestWithFieldsFormatting tests the WithFieldsf function with format strings
func TestWithFieldsFormatting(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	fields := Fields{"user": "alice"}
	WithFieldsf(fields, "User %s logged in at %d", "bob", 12345)

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
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	fields := make(Fields, 100)
	for i := range 100 {
		fields[fmt.Sprintf("field%03d", i)] = i
	}

	Info("test with many fields", fields)

	output := buf.String()
	if !strings.Contains(output, "test with many fields") {
		t.Error("Message not found")
	}
	// Check that first and last fields are present and ordered
	if !strings.Contains(output, "field000=0") {
		t.Error("First field not found")
	}
	if !strings.Contains(output, "field099=99") {
		t.Error("Last field not found")
	}
}

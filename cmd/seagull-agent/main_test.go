package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteCommandReportsVersion(t *testing.T) {
	var output bytes.Buffer
	handled, err := executeCommand([]string{"--version"}, &output)
	if err != nil {
		t.Fatalf("execute version: %v", err)
	}
	if !handled {
		t.Fatal("version command was not handled")
	}
	if !strings.Contains(output.String(), "seagull-agent") {
		t.Fatalf("unexpected version output: %q", output.String())
	}
}

func TestExecuteCommandRejectsInvalidCABundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(path, []byte("not a CA bundle"), 0o600); err != nil {
		t.Fatalf("write invalid CA bundle: %v", err)
	}
	handled, err := executeCommand([]string{"validate-ca", path}, &bytes.Buffer{})
	if !handled {
		t.Fatal("validate-ca command was not handled")
	}
	if err == nil {
		t.Fatal("invalid CA bundle was accepted")
	}
}

func TestExecuteCommandRejectsUnknownCommand(t *testing.T) {
	handled, err := executeCommand([]string{"unknown"}, &bytes.Buffer{})
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
}

package agentcfg

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicWriteFilePersistsContentAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credential")
	if err := AtomicWriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := AtomicWriteFile(path, []byte("second"), 0o640); err != nil {
		t.Fatalf("second write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(raw) != "second" {
		t.Fatalf("content=%q want second", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%o want 640", info.Mode().Perm())
	}
}

func TestAtomicWriteFileNeverExposesPartialConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first := bytes.Repeat([]byte("a"), 64*1024)
	second := bytes.Repeat([]byte("b"), 64*1024)
	if err := AtomicWriteFile(path, first, 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		payload := first
		if i%2 == 0 {
			payload = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := AtomicWriteFile(path, payload, 0o600); err != nil {
				t.Errorf("concurrent write: %v", err)
			}
		}()
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(raw, first) && !bytes.Equal(raw, second) {
		t.Fatalf("partial write length=%d", len(raw))
	}
}

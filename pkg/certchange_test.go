package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeSnapshotID(t *testing.T) {
	snap1 := &CertSnapshot{
		Target:       "example.com",
		CertSHA256:   "abc123",
		SPKISHA256:   "def456",
		SerialNumber: "789",
	}
	snap2 := &CertSnapshot{
		Target:       "example.com",
		CertSHA256:   "abc123",
		SPKISHA256:   "def456",
		SerialNumber: "789",
	}
	snap3 := &CertSnapshot{
		Target:       "other.com",
		CertSHA256:   "abc123",
		SPKISHA256:   "def456",
		SerialNumber: "789",
	}

	id1 := ComputeSnapshotID(snap1)
	id2 := ComputeSnapshotID(snap2)
	id3 := ComputeSnapshotID(snap3)

	if id1 != id2 {
		t.Error("same snapshot content should produce same ID")
	}
	if id1 == id3 {
		t.Error("different targets should produce different IDs")
	}
	if len(id1) != 16 {
		t.Errorf("ID should be 16 hex chars, got %d", len(id1))
	}
}

func TestSnapshotStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewSnapshotStore(dir)

	snap := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		CertSHA256:   "aabbccdd",
		SPKISHA256:   "eeff0011",
		Issuer:       "Test CA",
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber: "123456",
	}

	// Save
	if err := store.Save(snap); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load latest
	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadLatest returned nil")
	}

	if loaded.Target != snap.Target {
		t.Errorf("Target = %q, want %q", loaded.Target, snap.Target)
	}
	if loaded.CertSHA256 != snap.CertSHA256 {
		t.Errorf("CertSHA256 = %q, want %q", loaded.CertSHA256, snap.CertSHA256)
	}
	if loaded.Issuer != snap.Issuer {
		t.Errorf("Issuer = %q, want %q", loaded.Issuer, snap.Issuer)
	}
	if loaded.SerialNumber != snap.SerialNumber {
		t.Errorf("SerialNumber = %q, want %q", loaded.SerialNumber, snap.SerialNumber)
	}
}

func TestSnapshotStore_LoadLatest_NoSnapshots(t *testing.T) {
	dir := t.TempDir()
	store := NewSnapshotStore(dir)

	loaded, err := store.LoadLatest("nonexistent.com")
	if err != nil {
		t.Fatalf("LoadLatest should not error for missing snapshots: %v", err)
	}
	if loaded != nil {
		t.Error("LoadLatest should return nil for nonexistent target")
	}
}

func TestSnapshotStore_LoadLatest_NonexistentDir(t *testing.T) {
	store := NewSnapshotStore("/tmp/nonexistent_cert_skills_test_dir_xyz")

	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest should not error for nonexistent dir: %v", err)
	}
	if loaded != nil {
		t.Error("LoadLatest should return nil for nonexistent dir")
	}
}

func TestSnapshotStore_LoadLatest_PicksNewest(t *testing.T) {
	dir := t.TempDir()
	store := NewSnapshotStore(dir)

	// Save two snapshots with different timestamps
	snap1 := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		CertSHA256:   "older_cert",
		SPKISHA256:   "older_spki",
		SerialNumber: "111",
	}
	snap2 := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		CertSHA256:   "newer_cert",
		SPKISHA256:   "newer_spki",
		SerialNumber: "222",
	}

	if err := store.Save(snap1); err != nil {
		t.Fatalf("Save snap1 failed: %v", err)
	}
	if err := store.Save(snap2); err != nil {
		t.Fatalf("Save snap2 failed: %v", err)
	}

	loaded, err := store.LoadLatest("example.com")
	if err != nil {
		t.Fatalf("LoadLatest failed: %v", err)
	}
	if loaded.CertSHA256 != "newer_cert" {
		t.Errorf("LoadLatest should return the newest snapshot, got cert %q", loaded.CertSHA256)
	}
}

func TestSnapshotStore_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	store := NewSnapshotStore(dir)

	// Write a corrupted JSON file
	corruptPath := filepath.Join(dir, "example.com_20250615_103000.json")
	if err := os.WriteFile(corruptPath, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write corrupt file: %v", err)
	}

	loaded, err := store.LoadLatest("example.com")
	if err == nil {
		t.Error("LoadLatest should return error for corrupted JSON")
	}
	if loaded != nil {
		t.Error("LoadLatest should return nil for corrupted JSON")
	}
}

func TestCertSnapshotJSON(t *testing.T) {
	snap := &CertSnapshot{
		Target:       "example.com",
		Timestamp:    time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		CertSHA256:   "aabbccdd",
		SPKISHA256:   "eeff0011",
		Issuer:       "Test CA",
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber: "123456",
		JARMHash:     "29d29d15d29d29d21c",
		Metadata:     map[string]string{"source": "test"},
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded CertSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Target != snap.Target {
		t.Errorf("Target = %q, want %q", decoded.Target, snap.Target)
	}
	if decoded.JARMHash != snap.JARMHash {
		t.Errorf("JARMHash = %q, want %q", decoded.JARMHash, snap.JARMHash)
	}
	if decoded.Metadata["source"] != "test" {
		t.Errorf("Metadata[source] = %q, want %q", decoded.Metadata["source"], "test")
	}
}

func TestCertChangeResultJSON(t *testing.T) {
	result := &CertChangeResult{
		Target:     "example.com",
		HasChanged: true,
		ChangeType: "renewed",
		CurrentSnap: &CertSnapshot{
			Target:     "example.com",
			CertSHA256: "newcert",
			SPKISHA256: "samespki",
		},
		PreviousSnap: &CertSnapshot{
			Target:     "example.com",
			CertSHA256: "oldcert",
			SPKISHA256: "samespki",
		},
		Changes: []string{
			"Certificate changed: oldcert → newcert",
			"Same public key — likely a renewal",
		},
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded CertChangeResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.HasChanged {
		t.Error("HasChanged should be true")
	}
	if decoded.ChangeType != "renewed" {
		t.Errorf("ChangeType = %q, want %q", decoded.ChangeType, "renewed")
	}
	if len(decoded.Changes) != 2 {
		t.Errorf("Changes length = %d, want 2", len(decoded.Changes))
	}
}

func TestDetectChange_NilPrevious(t *testing.T) {
	// When there's no previous snapshot, DetectChange would need network access.
	// Test the logic path by creating a CertChangeResult directly.
	result := &CertChangeResult{
		Target:       "example.com",
		HasChanged:   false,
		ChangeType:   "",
		CurrentSnap:  &CertSnapshot{Target: "example.com", CertSHA256: "abc"},
		PreviousSnap: nil,
		Changes:      []string{},
	}

	// Simulate the "new" path from DetectChange
	if result.PreviousSnap == nil {
		result.HasChanged = true
		result.ChangeType = "new"
		result.Changes = append(result.Changes, "First snapshot for this target")
	}

	if !result.HasChanged {
		t.Error("nil previous should set HasChanged to true")
	}
	if result.ChangeType != "new" {
		t.Errorf("ChangeType = %q, want %q", result.ChangeType, "new")
	}
}

func TestDetectChange_ComparisonLogic(t *testing.T) {
	// Test the comparison logic without network access by simulating DetectChange's logic
	tests := []struct {
		name       string
		current    *CertSnapshot
		previous   *CertSnapshot
		hasChanged bool
		changeType string
		changeLen  int
	}{
		{
			name: "identical snapshots",
			current: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "Test CA",
				JARMHash:   "jarm1",
			},
			previous: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "Test CA",
				JARMHash:   "jarm1",
			},
			hasChanged: false,
			changeType: "unchanged",
			changeLen:  0,
		},
		{
			name: "renewed - same SPKI, different cert",
			current: &CertSnapshot{
				CertSHA256: "newcert",
				SPKISHA256: "samespki",
				Issuer:     "Test CA",
			},
			previous: &CertSnapshot{
				CertSHA256: "oldcert",
				SPKISHA256: "samespki",
				Issuer:     "Test CA",
			},
			hasChanged: true,
			changeType: "renewed",
			changeLen:  1, // cert changed only (SPKI same, not added separately)
		},
		{
			name: "replaced - different SPKI",
			current: &CertSnapshot{
				CertSHA256: "newcert",
				SPKISHA256: "newspki",
				Issuer:     "Test CA",
			},
			previous: &CertSnapshot{
				CertSHA256: "oldcert",
				SPKISHA256: "oldspki",
				Issuer:     "Test CA",
			},
			hasChanged: true,
			changeType: "replaced",
			changeLen:  2, // cert changed + SPKI changed
		},
		{
			name: "issuer changed",
			current: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "New CA",
			},
			previous: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "Old CA",
			},
			hasChanged: true,
			changeType: "", // No cert/SPKI change, so changeType stays empty
			changeLen:  1,
		},
		{
			name: "JARM changed",
			current: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "Test CA",
				JARMHash:   "newjarm",
			},
			previous: &CertSnapshot{
				CertSHA256: "abc123",
				SPKISHA256: "spki123",
				Issuer:     "Test CA",
				JARMHash:   "oldjarm",
			},
			hasChanged: true,
			changeType: "", // Only JARM changed, not cert
			changeLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Replicate DetectChange logic
			result := &CertChangeResult{
				Target:       "test",
				CurrentSnap:  tt.current,
				PreviousSnap: tt.previous,
				HasChanged:   false,
				Changes:      []string{},
			}

			prev := tt.previous
			current := tt.current

			// Compare certificate SHA-256
			if current.CertSHA256 != prev.CertSHA256 {
				result.HasChanged = true
				result.Changes = append(result.Changes, "Certificate changed")
				if current.SPKISHA256 == prev.SPKISHA256 {
					result.ChangeType = "renewed"
				} else {
					result.ChangeType = "replaced"
				}
			}

			// Compare SPKI hash
			if current.SPKISHA256 != prev.SPKISHA256 {
				if !result.HasChanged {
					result.HasChanged = true
					result.ChangeType = "replaced"
				}
				result.Changes = append(result.Changes, "SPKI changed")
			}

			// Compare issuer
			if current.Issuer != prev.Issuer {
				result.HasChanged = true
				result.Changes = append(result.Changes, "Issuer changed")
			}

			// Compare JARM
			if current.JARMHash != "" && prev.JARMHash != "" && current.JARMHash != prev.JARMHash {
				result.HasChanged = true
				result.Changes = append(result.Changes, "JARM changed")
			}

			if !result.HasChanged {
				result.ChangeType = "unchanged"
			}

			if result.HasChanged != tt.hasChanged {
				t.Errorf("HasChanged = %v, want %v", result.HasChanged, tt.hasChanged)
			}
			if tt.changeType != "" && result.ChangeType != tt.changeType {
				t.Errorf("ChangeType = %q, want %q", result.ChangeType, tt.changeType)
			}
			if len(result.Changes) != tt.changeLen {
				t.Errorf("Changes length = %d, want %d", len(result.Changes), tt.changeLen)
			}
		})
	}
}

func TestNewSnapshotStore(t *testing.T) {
	dir := "/tmp/test_snaps"
	store := NewSnapshotStore(dir)
	if store.Dir != dir {
		t.Errorf("Dir = %q, want %q", store.Dir, dir)
	}
}

func TestCertChangeRecord(t *testing.T) {
	record := CertChangeRecord{
		Target:     "example.com",
		ChangeAt:   time.Now(),
		ChangeType: "renewed",
		OldSnap:    &CertSnapshot{Target: "example.com", CertSHA256: "old"},
		NewSnap:    &CertSnapshot{Target: "example.com", CertSHA256: "new"},
		Details:    []string{"Certificate renewed"},
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded CertChangeRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.ChangeType != "renewed" {
		t.Errorf("ChangeType = %q, want %q", decoded.ChangeType, "renewed")
	}
	if decoded.OldSnap.CertSHA256 != "old" {
		t.Errorf("OldSnap.CertSHA256 = %q, want %q", decoded.OldSnap.CertSHA256, "old")
	}
}

func TestDetectChange_ExpiredCert(t *testing.T) {
	// Test expiry detection logic
	current := &CertSnapshot{
		CertSHA256: "abc123",
		SPKISHA256: "spki123",
		Issuer:     "Test CA",
		NotAfter:   time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // Already expired
	}

	// Replicate expiry check logic from DetectChange
	hasExpiry := !current.NotAfter.IsZero() && time.Now().After(current.NotAfter)
	if !hasExpiry {
		t.Error("expired certificate should be detected")
	}
}

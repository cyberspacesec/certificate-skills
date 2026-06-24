package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CertSnapshot represents a certificate fingerprint snapshot at a point in time.
type CertSnapshot struct {
	Target       string            `json:"target"`
	Timestamp    time.Time         `json:"timestamp"`
	CertSHA256   string            `json:"cert_sha256"`
	SPKISHA256   string            `json:"spki_sha256"`
	Issuer       string            `json:"issuer"`
	NotBefore    time.Time         `json:"not_before"`
	NotAfter     time.Time         `json:"not_after"`
	SerialNumber string            `json:"serial_number"`
	JARMHash     string            `json:"jarm_hash,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// CertChangeRecord represents a detected change between two snapshots.
type CertChangeRecord struct {
	Target     string        `json:"target"`
	ChangeAt   time.Time     `json:"change_at"`
	ChangeType string        `json:"change_type"` // "new", "renewed", "replaced", "revoked", "expired"
	OldSnap    *CertSnapshot `json:"old_snapshot,omitempty"`
	NewSnap    *CertSnapshot `json:"new_snapshot,omitempty"`
	Details    []string      `json:"details"`
}

// CertChangeResult contains the result of a change detection check.
type CertChangeResult struct {
	Target       string        `json:"target"`
	HasChanged   bool          `json:"has_changed"`
	ChangeType   string        `json:"change_type,omitempty"`
	CurrentSnap  *CertSnapshot `json:"current_snapshot"`
	PreviousSnap *CertSnapshot `json:"previous_snapshot,omitempty"`
	Changes      []string      `json:"changes,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// SnapshotStore manages certificate snapshots on disk.
type SnapshotStore struct {
	Dir string `json:"dir"`
}

// NewSnapshotStore creates a new snapshot store in the given directory.
func NewSnapshotStore(dir string) *SnapshotStore {
	return &SnapshotStore{Dir: dir}
}

// TakeSnapshot captures the current certificate state of a target.
func TakeSnapshot(target string) (*CertSnapshot, error) {
	snap := &CertSnapshot{
		Target:    target,
		Timestamp: time.Now(),
	}

	// Get certificate info
	sslInfo, err := GetCertFromDomain(target)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert from %s: %v", target, err)
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return nil, ErrCertNotFound
	}

	cert := sslInfo.PeerCerts.Certificates[0]

	if sha, ok := cert.Fingerprints["sha256"]; ok {
		snap.CertSHA256 = sha
	}
	if spki, ok := cert.Fingerprints["public_key_sha256"]; ok {
		snap.SPKISHA256 = spki
	}
	snap.Issuer = cert.Issuer
	snap.NotBefore = cert.NotBefore
	snap.NotAfter = cert.NotAfter
	snap.SerialNumber = cert.SerialNumber

	// Get JARM hash (non-blocking, best effort)
	jarmResult, err := JARMScan(target)
	if err == nil && jarmResult.JARMHash != "" {
		snap.JARMHash = jarmResult.JARMHash
	}

	return snap, nil
}

// DetectChange compares the current certificate state with a previous snapshot.
func DetectChange(target string, prev *CertSnapshot) (*CertChangeResult, error) {
	current, err := TakeSnapshot(target)
	if err != nil {
		return nil, err
	}

	result := &CertChangeResult{
		Target:       target,
		CurrentSnap:  current,
		PreviousSnap: prev,
		HasChanged:   false,
		Changes:      []string{},
	}

	if prev == nil {
		result.HasChanged = true
		result.ChangeType = "new"
		result.Changes = append(result.Changes, "First snapshot for this target")
		return result, nil
	}

	// Compare certificate SHA-256
	if current.CertSHA256 != prev.CertSHA256 {
		result.HasChanged = true
		result.Changes = append(result.Changes, fmt.Sprintf("Certificate changed: %s → %s", prev.CertSHA256, current.CertSHA256))

		// Determine change type
		if current.SPKISHA256 == prev.SPKISHA256 {
			result.ChangeType = "renewed" // Same key, new cert (typical renewal)
			result.Changes = append(result.Changes, "Same public key — likely a renewal")
		} else {
			result.ChangeType = "replaced" // Different key entirely
			result.Changes = append(result.Changes, "Different public key — certificate was replaced")
		}
	}

	// Compare SPKI hash
	if current.SPKISHA256 != prev.SPKISHA256 {
		if !result.HasChanged {
			result.HasChanged = true
			result.ChangeType = "replaced"
		}
		result.Changes = append(result.Changes, fmt.Sprintf("SPKI changed: %s → %s", prev.SPKISHA256, current.SPKISHA256))
	}

	// Compare issuer
	if current.Issuer != prev.Issuer {
		result.HasChanged = true
		result.Changes = append(result.Changes, fmt.Sprintf("Issuer changed: %s → %s", prev.Issuer, current.Issuer))
	}

	// Compare JARM
	if current.JARMHash != "" && prev.JARMHash != "" && current.JARMHash != prev.JARMHash {
		result.HasChanged = true
		result.Changes = append(result.Changes, fmt.Sprintf("JARM changed: %s → %s", prev.JARMHash, current.JARMHash))
	}

	// Check for expiry
	if !current.NotAfter.IsZero() && time.Now().After(current.NotAfter) {
		result.HasChanged = true
		if result.ChangeType == "" {
			result.ChangeType = "expired"
		}
		result.Changes = append(result.Changes, "Certificate has expired")
	}

	if !result.HasChanged {
		result.ChangeType = "unchanged"
	}

	return result, nil
}

// Save writes a snapshot to disk.
func (s *SnapshotStore) Save(snap *CertSnapshot) error {
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		return fmt.Errorf("failed to create snapshot directory: %v", err)
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %v", err)
	}

	filename := fmt.Sprintf("%s_%s.json", sanitizeFilename(snap.Target), snap.Timestamp.Format("20060102_150405"))
	path := filepath.Join(s.Dir, filename)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write snapshot: %v", err)
	}

	return nil
}

// LoadLatest loads the most recent snapshot for a target.
func (s *SnapshotStore) LoadLatest(target string) (*CertSnapshot, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No snapshots yet
		}
		return nil, fmt.Errorf("failed to read snapshot directory: %v", err)
	}

	prefix := sanitizeFilename(target) + "_"
	var matches []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if strings.HasPrefix(entry.Name(), prefix) {
			matches = append(matches, entry.Name())
		}
	}

	if len(matches) == 0 {
		return nil, nil // No snapshots for this target
	}

	// Sort by filename (which includes timestamp) to get the latest
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))

	data, err := os.ReadFile(filepath.Join(s.Dir, matches[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %v", err)
	}

	var snap CertSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %v", err)
	}

	return &snap, nil
}

// ComputeSnapshotID computes a unique ID for a snapshot based on its content.
func ComputeSnapshotID(snap *CertSnapshot) string {
	h := sha256.New()
	h.Write([]byte(snap.Target))
	h.Write([]byte(snap.CertSHA256))
	h.Write([]byte(snap.SPKISHA256))
	h.Write([]byte(snap.SerialNumber))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

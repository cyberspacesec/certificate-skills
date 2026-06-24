package pkg

import (
	"crypto/x509"
	"sort"
	"time"
)

// CertificateTimelineEvent describes one lifecycle transition for a mapped target.
type CertificateTimelineEvent struct {
	Target  string        `json:"target"`
	At      time.Time     `json:"at"`
	Type    string        `json:"type"`
	OldSnap *CertSnapshot `json:"old_snapshot,omitempty"`
	NewSnap *CertSnapshot `json:"new_snapshot,omitempty"`
	Details []string      `json:"details,omitempty"`
}

// CertificateTimeline groups ordered lifecycle events by target.
type CertificateTimeline struct {
	EventsByTarget map[string][]CertificateTimelineEvent `json:"events_by_target"`
	Events         []CertificateTimelineEvent            `json:"events"`
}

// BuildCertificateTimeline derives lifecycle events from snapshots.
func BuildCertificateTimeline(snapshots []CertSnapshot, now time.Time) CertificateTimeline {
	if now.IsZero() {
		now = time.Now()
	}

	byTarget := make(map[string][]CertSnapshot)
	for _, snap := range snapshots {
		byTarget[snap.Target] = append(byTarget[snap.Target], snap)
	}
	for target := range byTarget {
		sort.Slice(byTarget[target], func(i, j int) bool {
			return byTarget[target][i].Timestamp.Before(byTarget[target][j].Timestamp)
		})
	}

	timeline := CertificateTimeline{EventsByTarget: make(map[string][]CertificateTimelineEvent)}
	for target, snaps := range byTarget {
		var prev *CertSnapshot
		for i := range snaps {
			current := snaps[i]
			if prev == nil {
				timeline.add(CertificateTimelineEvent{
					Target:  target,
					At:      current.Timestamp,
					Type:    "first_seen",
					NewSnap: copySnapshot(&current),
					Details: []string{"First observed certificate for target"},
				})
			} else {
				for _, event := range compareTimelineSnapshots(prev, &current) {
					timeline.add(event)
				}
			}
			if !current.NotAfter.IsZero() && !now.Before(current.NotAfter) {
				timeline.add(CertificateTimelineEvent{
					Target:  target,
					At:      current.NotAfter,
					Type:    "expired",
					NewSnap: copySnapshot(&current),
					Details: []string{"Certificate validity period ended"},
				})
			}
			prev = &current
		}
	}

	sort.Slice(timeline.Events, func(i, j int) bool {
		if timeline.Events[i].At.Equal(timeline.Events[j].At) {
			return timeline.Events[i].Target < timeline.Events[j].Target
		}
		return timeline.Events[i].At.Before(timeline.Events[j].At)
	})
	for target := range timeline.EventsByTarget {
		sort.Slice(timeline.EventsByTarget[target], func(i, j int) bool {
			return timeline.EventsByTarget[target][i].At.Before(timeline.EventsByTarget[target][j].At)
		})
	}
	return timeline
}

// SnapshotsFromCertificateAssets converts mapped certificate observations into timeline snapshots.
func SnapshotsFromCertificateAssets(assets []CertificateAsset) []CertSnapshot {
	snapshots := make([]CertSnapshot, 0, len(assets))
	for _, asset := range assets {
		if asset.Cert == nil {
			continue
		}
		target := asset.Target.Address()
		if target == ":443" {
			target = asset.Target.Host
		}
		timestamp := asset.ObservedAt
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		snapshots = append(snapshots, SnapshotFromCertificate(target, asset.Cert, timestamp, nil))
	}
	return snapshots
}

// SnapshotFromCertificate builds a CertSnapshot from a parsed certificate.
func SnapshotFromCertificate(target string, cert *x509.Certificate, observedAt time.Time, metadata map[string]string) CertSnapshot {
	if cert == nil {
		return CertSnapshot{Target: target, Timestamp: observedAt, Metadata: metadata}
	}
	metaCopy := make(map[string]string, len(metadata))
	for k, v := range metadata {
		metaCopy[k] = v
	}
	return CertSnapshot{
		Target:       target,
		Timestamp:    observedAt,
		CertSHA256:   computeHashHex(cert.Raw),
		SPKISHA256:   computeHashHex(cert.RawSubjectPublicKeyInfo),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Metadata:     metaCopy,
	}
}

func (t *CertificateTimeline) add(event CertificateTimelineEvent) {
	t.Events = append(t.Events, event)
	t.EventsByTarget[event.Target] = append(t.EventsByTarget[event.Target], event)
}

func compareTimelineSnapshots(prev, current *CertSnapshot) []CertificateTimelineEvent {
	var events []CertificateTimelineEvent
	if prev == nil || current == nil {
		return events
	}

	if current.CertSHA256 != prev.CertSHA256 {
		eventType := "replaced"
		details := []string{"Certificate fingerprint changed"}
		if current.SPKISHA256 == prev.SPKISHA256 {
			eventType = "renewed"
			details = append(details, "Public key stayed the same")
		} else {
			details = append(details, "Public key changed")
		}
		events = append(events, CertificateTimelineEvent{
			Target:  current.Target,
			At:      current.Timestamp,
			Type:    eventType,
			OldSnap: copySnapshot(prev),
			NewSnap: copySnapshot(current),
			Details: details,
		})
	}

	if current.Issuer != prev.Issuer {
		events = append(events, CertificateTimelineEvent{
			Target:  current.Target,
			At:      current.Timestamp,
			Type:    "issuer_changed",
			OldSnap: copySnapshot(prev),
			NewSnap: copySnapshot(current),
			Details: []string{"Issuer changed"},
		})
	}

	return events
}

func copySnapshot(snap *CertSnapshot) *CertSnapshot {
	if snap == nil {
		return nil
	}
	cp := *snap
	if snap.Metadata != nil {
		cp.Metadata = make(map[string]string, len(snap.Metadata))
		for k, v := range snap.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

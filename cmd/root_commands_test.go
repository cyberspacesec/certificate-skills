package main

import "testing"

func TestRootCommandCount(t *testing.T) {
	const expectedCommands = 51

	if got := len(rootCmd.Commands()); got != expectedCommands {
		t.Fatalf("root command count = %d, want %d", got, expectedCommands)
	}
}

func TestMatchFingerprintsAlias(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"match-fingerprints"})
	if err != nil {
		t.Fatalf("find match-fingerprints: %v", err)
	}
	if cmd != matchFingerprintsCmd {
		t.Fatalf("match-fingerprints resolved to %q, want %q", cmd.Use, matchFingerprintsCmd.Use)
	}
}

func TestMatchFingerprintByHashCommandRegistered(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"match-fingerprint-by-hash"})
	if err != nil {
		t.Fatalf("find match-fingerprint-by-hash: %v", err)
	}
	if cmd != matchFingerprintByHashCmd {
		t.Fatalf("match-fingerprint-by-hash resolved to %q, want %q", cmd.Use, matchFingerprintByHashCmd.Use)
	}
}

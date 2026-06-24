package display

import (
	"encoding/csv"
	"fmt"
	"os"
)

// WriteCSV writes a CSV file with the given headers and rows.
// Each row is a string slice matching the header order.
func WriteCSV(headers []string, rows [][]string, outputPath string) error {
	var w *csv.Writer

	if outputPath == "" || outputPath == "-" {
		w = csv.NewWriter(os.Stdout)
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %v", err)
		}
		defer f.Close()
		w = csv.NewWriter(f)
	}

	// Write header
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	// Write rows
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %v", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("CSV write error: %v", err)
	}

	return nil
}

// FormatInt formats an integer as a string.
func FormatInt(v int) string {
	return fmt.Sprintf("%d", v)
}

// FormatBool formats a boolean as a string.
func FormatBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

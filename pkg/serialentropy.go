package pkg

import (
	"crypto/x509"
	"fmt"
	"math"
	"math/big"
	"math/bits"
)

// SerialEntropyResult represents the result of serial number entropy analysis.
type SerialEntropyResult struct {
	Target      string  `json:"target"`
	SerialHex   string  `json:"serial_hex"`
	BitLength   int     `json:"bit_length"`
	IsCompliant bool    `json:"is_compliant"`  // CA/B BR requires >= 64 bits entropy
	EntropyEstimate float64 `json:"entropy_estimate"` // Estimated Shannon entropy bits
	HammingWeight   int     `json:"hamming_weight"`    // Number of 1 bits
	HammingRatio    float64 `json:"hamming_ratio"`     // Ratio of 1 bits to total bits
	IsSequential    bool    `json:"is_sequential"`     // Looks like sequential numbering
	Issues      []string `json:"issues,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

// CheckSerialEntropy analyzes the serial number entropy of a certificate.
// CA/Browser Forum Baseline Requirements mandate at least 64 bits of entropy.
func CheckSerialEntropy(target string) (*SerialEntropyResult, error) {
	result := &SerialEntropyResult{
		IsCompliant: true,
	}

	conn, err := TLSDial(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	result.Target = target
	analyzeSerialNumber(cert, result)

	return result, nil
}

// AnalyzeSerialNumberFromCert analyzes serial number entropy from a parsed certificate.
func AnalyzeSerialNumberFromCert(cert *x509.Certificate) *SerialEntropyResult {
	result := &SerialEntropyResult{
		Target:      cert.Subject.CommonName,
		IsCompliant: true,
	}
	analyzeSerialNumber(cert, result)
	return result
}

func analyzeSerialNumber(cert *x509.Certificate, result *SerialEntropyResult) {
	serial := cert.SerialNumber
	if serial == nil {
		result.IsCompliant = false
		result.Issues = append(result.Issues, "Certificate has no serial number")
		result.Detail = "Missing serial number"
		return
	}

	result.SerialHex = fmt.Sprintf("%x", serial)
	result.BitLength = serial.BitLen()

	// CA/B BR requires at least 64 bits of entropy
	if result.BitLength < 64 {
		result.IsCompliant = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("Serial number is only %d bits (CA/B BR requires >= 64 bits)", result.BitLength))
	}

	// Calculate Hamming weight (number of set bits)
	bytes := serial.Bytes()
	totalBits := len(bytes) * 8
	setBits := 0
	for _, b := range bytes {
		setBits += bits.OnesCount8(b)
	}
	result.HammingWeight = setBits
	if totalBits > 0 {
		result.HammingRatio = float64(setBits) / float64(totalBits)
	}

	// Estimate Shannon entropy of the serial number bytes
	result.EntropyEstimate = estimateShannonEntropy(bytes)

	// Check for sequential patterns
	result.IsSequential = isSequentialSerial(serial)

	// Low entropy warning (entropy < 3.0 bits per byte indicates low randomness)
	if result.EntropyEstimate < 3.0 && result.BitLength >= 64 {
		result.IsCompliant = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("Low estimated entropy (%.2f bits/byte) suggests insufficient randomness", result.EntropyEstimate))
	}

	// Hamming ratio check - too close to 0 or 1 indicates bias
	if result.HammingRatio < 0.3 || result.HammingRatio > 0.7 {
		if result.BitLength >= 64 {
			result.Issues = append(result.Issues,
				fmt.Sprintf("Hamming ratio %.3f indicates possible bias in serial generation", result.HammingRatio))
		}
	}

	// Sequential serial check
	if result.IsSequential {
		result.IsCompliant = false
		result.Issues = append(result.Issues,
			"Serial number appears sequential (predictable), violating CA/B BR entropy requirements")
	}

	// Build detail string
	if result.IsCompliant {
		result.Detail = fmt.Sprintf("Serial number has %d bits with %.2f bits/byte entropy", result.BitLength, result.EntropyEstimate)
	} else {
		result.Detail = fmt.Sprintf("Serial number issues: %s", fmt.Sprintf("%v", result.Issues))
	}
}

// estimateShannonEntropy estimates the Shannon entropy in bits per byte.
func estimateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	var entropy float64
	n := float64(len(data))
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * log2(p)
		}
	}

	return entropy
}

// log2 computes log base 2 using math package.
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log2(x)
}

// isSequentialSerial checks if a serial number appears to be sequential.
// Sequential serials have very small differences between them and are predictable.
func isSequentialSerial(serial *big.Int) bool {
	if serial == nil {
		return false
	}

	// Check if the serial number is very small (< 1000)
	if serial.Cmp(big.NewInt(1000)) < 0 {
		return true
	}

	// Check if the serial number is a power of 10 or close to it
	// (indicates decimal sequential numbering like 1001, 1002, etc.)
	ten := big.NewInt(10)
	remainder := new(big.Int)
	for power := 1; power <= 20; power++ {
		tenPower := new(big.Int).Exp(ten, big.NewInt(int64(power)), nil)
		remainder.Mod(serial, tenPower)
		if remainder.Sign() == 0 {
			// Serial is a multiple of a power of 10
			return true
		}
	}

	// Check if most significant bytes are zeros (low entropy prefix)
	bytes := serial.Bytes()
	if len(bytes) > 8 {
		leadingZeros := 0
		for _, b := range bytes[:len(bytes)-8] {
			if b == 0 {
				leadingZeros++
			}
		}
		if leadingZeros > len(bytes)-8 {
			return true
		}
	}

	return false
}

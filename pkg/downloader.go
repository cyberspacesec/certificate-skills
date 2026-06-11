package pkg

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"
)

// DownloadResult 证书下载结果
type DownloadResult struct {
	Target      string   `json:"target"`
	SavedFiles  []string `json:"saved_files"`
	ChainLength int      `json:"chain_length"`
	Message     string   `json:"message"`
}

// DownloadCertsFromDomain 从域名下载证书链并保存到文件
func DownloadCertsFromDomain(target string, outputDir string) (*DownloadResult, error) {
	if outputDir == "" {
		outputDir = "."
	}

	// 解析主机名用于文件命名
	host, _ := parseHostPort(target)

	savedFiles := []string{}

	// 连接到目标获取原始证书
	conn, err := TLSDial(target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	// 保存整个证书链到单个文件
	chainPath := fmt.Sprintf("%s/%s-chain.pem", outputDir, host)
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain file: %v", err)
	}
	defer chainFile.Close()

	for _, cert := range certs {
		err := pem.Encode(chainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write certificate to chain file: %v", err)
		}
	}
	savedFiles = append(savedFiles, chainPath)

	// 保存叶子证书到单独文件
	if len(certs) > 0 {
		leafPath := fmt.Sprintf("%s/%s.pem", outputDir, host)
		leafFile, err := os.Create(leafPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create leaf cert file: %v", err)
		}
		defer leafFile.Close()

		err = pem.Encode(leafFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[0].Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write leaf certificate: %v", err)
		}
		savedFiles = append(savedFiles, leafPath)
	}

	result := &DownloadResult{
		Target:      target,
		SavedFiles:  savedFiles,
		ChainLength: len(certs),
		Message:     fmt.Sprintf("Downloaded %d certificates for %s", len(certs), target),
	}

	return result, nil
}

// TLSDial 建立TLS连接并返回连接对象（公开函数，供 comparator 等模块复用）
func TLSDial(target string) (*tls.Conn, error) {
	host, port := parseHostPort(target)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%s: %v", host, port, err)
	}

	return conn, nil
}

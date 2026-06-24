package pkg

import (
	"crypto/x509"
	"fmt"
	"sort"
)

// TrustChainNode is one unique certificate or issuer in a trust-chain graph.
type TrustChainNode struct {
	ID           string   `json:"id"`
	CertSHA256   string   `json:"cert_sha256,omitempty"`
	SPKISHA256   string   `json:"spki_sha256,omitempty"`
	Subject      string   `json:"subject"`
	CommonName   string   `json:"common_name,omitempty"`
	OrgKey       string   `json:"org_key,omitempty"`
	IsCA         bool     `json:"is_ca"`
	SelfSigned   bool     `json:"self_signed"`
	ChainIndexes []int    `json:"chain_indexes,omitempty"`
	Targets      []string `json:"targets,omitempty"`
}

// TrustChainEdge links issuer to subject for one observed certificate relation.
type TrustChainEdge struct {
	FromIssuerID string   `json:"from_issuer_id"`
	ToSubjectID  string   `json:"to_subject_id"`
	Relation     string   `json:"relation"`
	ChainIndexes []int    `json:"chain_indexes,omitempty"`
	Targets      []string `json:"targets,omitempty"`
}

// TrustChainTopology represents issuer-to-subject relationships across chains.
type TrustChainTopology struct {
	Nodes  []TrustChainNode `json:"nodes"`
	Edges  []TrustChainEdge `json:"edges"`
	Roots  []string         `json:"roots,omitempty"`
	Leaves []string         `json:"leaves,omitempty"`
}

// BuildTrustChainTopology builds an issuer graph from certificate chains.
func BuildTrustChainTopology(chains [][]*x509.Certificate) TrustChainTopology {
	observed := make([]CertificateAsset, 0, len(chains))
	for i, chain := range chains {
		target := ScanTarget{Host: fmt.Sprintf("chain-%d", i), Port: 443}
		if len(chain) > 0 {
			observed = append(observed, CertificateAsset{Target: target, Cert: chain[0], Chain: chain})
		}
	}
	return BuildTrustChainTopologyFromAssets(observed)
}

// BuildTrustChainTopologyFromAssets builds an issuer graph from mapped assets.
func BuildTrustChainTopologyFromAssets(assets []CertificateAsset) TrustChainTopology {
	nodeByID := make(map[string]*TrustChainNode)
	edgeByKey := make(map[string]*TrustChainEdge)
	incoming := make(map[string]bool)
	outgoing := make(map[string]bool)

	for chainIndex, asset := range assets {
		chain := asset.Chain
		if len(chain) == 0 && asset.Cert != nil {
			chain = []*x509.Certificate{asset.Cert}
		}
		target := asset.Target.Address()
		for certIndex, cert := range chain {
			if cert == nil {
				continue
			}
			subjectID := trustNodeID(cert)
			addTrustNode(nodeByID, subjectID, cert, chainIndex, target)
			if certIndex+1 < len(chain) && chain[certIndex+1] != nil {
				issuer := chain[certIndex+1]
				issuerID := trustNodeID(issuer)
				addTrustNode(nodeByID, issuerID, issuer, chainIndex, target)
				addTrustEdge(edgeByKey, issuerID, subjectID, "issued", chainIndex, target)
				incoming[subjectID] = true
				outgoing[issuerID] = true
			} else if cert.CheckSignatureFrom(cert) == nil {
				addTrustEdge(edgeByKey, subjectID, subjectID, "self_signed", chainIndex, target)
			}
		}
	}

	topology := TrustChainTopology{
		Nodes: make([]TrustChainNode, 0, len(nodeByID)),
		Edges: make([]TrustChainEdge, 0, len(edgeByKey)),
	}
	for _, node := range nodeByID {
		sort.Ints(node.ChainIndexes)
		sort.Strings(node.Targets)
		topology.Nodes = append(topology.Nodes, *node)
		if !incoming[node.ID] {
			topology.Roots = append(topology.Roots, node.ID)
		}
		if !outgoing[node.ID] {
			topology.Leaves = append(topology.Leaves, node.ID)
		}
	}
	for _, edge := range edgeByKey {
		sort.Ints(edge.ChainIndexes)
		sort.Strings(edge.Targets)
		topology.Edges = append(topology.Edges, *edge)
	}

	sort.Slice(topology.Nodes, func(i, j int) bool { return topology.Nodes[i].ID < topology.Nodes[j].ID })
	sort.Slice(topology.Edges, func(i, j int) bool {
		if topology.Edges[i].FromIssuerID == topology.Edges[j].FromIssuerID {
			return topology.Edges[i].ToSubjectID < topology.Edges[j].ToSubjectID
		}
		return topology.Edges[i].FromIssuerID < topology.Edges[j].FromIssuerID
	})
	sort.Strings(topology.Roots)
	sort.Strings(topology.Leaves)
	return topology
}

func trustNodeID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if hash := computeHashHex(cert.Raw); hash != "" {
		return hash
	}
	return computeHashHex([]byte(cert.Subject.String() + "\x00" + cert.SerialNumber.String()))
}

func addTrustNode(nodes map[string]*TrustChainNode, id string, cert *x509.Certificate, chainIndex int, target string) {
	if id == "" || cert == nil {
		return
	}
	node := nodes[id]
	if node == nil {
		ns := NormalizeCertificateSubject(cert)
		node = &TrustChainNode{
			ID:         id,
			CertSHA256: computeHashHex(cert.Raw),
			SPKISHA256: computeHashHex(cert.RawSubjectPublicKeyInfo),
			Subject:    cert.Subject.String(),
			CommonName: cert.Subject.CommonName,
			OrgKey:     ns.OrgKey,
			IsCA:       cert.IsCA,
			SelfSigned: cert.CheckSignatureFrom(cert) == nil,
		}
		nodes[id] = node
	}
	node.ChainIndexes = appendUniqueInt(node.ChainIndexes, chainIndex)
	if target != "" {
		node.Targets = appendUniqueString(node.Targets, target)
	}
}

func addTrustEdge(edges map[string]*TrustChainEdge, issuerID, subjectID, relation string, chainIndex int, target string) {
	key := issuerID + "\x00" + subjectID + "\x00" + relation
	edge := edges[key]
	if edge == nil {
		edge = &TrustChainEdge{FromIssuerID: issuerID, ToSubjectID: subjectID, Relation: relation}
		edges[key] = edge
	}
	edge.ChainIndexes = appendUniqueInt(edge.ChainIndexes, chainIndex)
	if target != "" {
		edge.Targets = appendUniqueString(edge.Targets, target)
	}
}

func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

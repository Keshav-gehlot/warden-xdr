package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Keshav-gehlot/warden-xdr/internal/proto"
)

// Client talks to the manager over HTTPS. The manager certificate is pinned
// by SHA-256 fingerprint: either configured explicitly or learned at first
// enrollment (trust on first use) and stored in the agent state.
type Client struct {
	base        string
	http        *http.Client
	fingerprint string // pinned fingerprint (hex); "" until learned
	seen        string // fingerprint presented in the last handshake
	agentID     string
	key         string
	system      bool // chain verified by OS trust store; no pinning
}

// NewClient creates a manager client. tlsMode "pin" (default) pins the
// certificate fingerprint; "system" verifies the certificate chain against the
// OS trust store instead (use behind a public proxy such as Render, whose
// certificates rotate).
func NewClient(manager, fingerprint, tlsMode string) *Client {
	host := strings.TrimPrefix(manager, "https://")
	c := &Client{base: "https://" + host, fingerprint: strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))}
	if tlsMode == "system" {
		c.fingerprint = ""
		c.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second}}
		c.system = true
		return c
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // replaced by VerifyConnection pinning below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no server certificate")
				}
				fp := certFP(cs.PeerCertificates[0])
				c.seen = fp
				if c.fingerprint != "" && fp != c.fingerprint {
					return fmt.Errorf("manager certificate fingerprint mismatch: got %s, pinned %s", fp, c.fingerprint)
				}
				return nil
			},
		},
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	c.http = &http.Client{Transport: tr, Timeout: 60 * time.Second}
	return c
}

func certFP(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func (c *Client) SetIdentity(id, key string) { c.agentID, c.key = id, key }

func (c *Client) Enroll(req proto.EnrollRequest) (*proto.EnrollResponse, error) {
	b, _ := json.Marshal(req)
	resp, err := c.http.Post(c.base+"/v1/enroll", "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("enroll: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out proto.EnrollResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if c.fingerprint == "" && !c.system {
		c.fingerprint = c.seen // TOFU: pin what we saw during successful enrollment
	}
	return &out, nil
}

// ErrUnauthorized means the manager no longer knows this agent (deleted or re-keyed).
var ErrUnauthorized = errors.New("manager rejected agent credentials")

// Post sends a signed, gzip-compressed JSON request and decodes the reply.
func (c *Client) Post(path string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write(raw)
	zw.Close()
	body := zb.Bytes()
	ts := time.Now().Unix()
	req, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set(proto.HeaderAgentID, c.agentID)
	req.Header.Set(proto.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(proto.HeaderSignature, proto.Sign(c.key, c.agentID, ts, "POST", path, body))
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode == 401 {
		return fmt.Errorf("%w: %s", ErrUnauthorized, strings.TrimSpace(string(rb)))
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(rb)))
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

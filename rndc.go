// Package rndc provides a client implementation for the BIND Remote Name Daemon Control (RNDC) protocol.
// It allows Go applications to communicate with BIND DNS servers using the RNDC protocol for administrative tasks.
package rndc

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// algosMap maps HMAC algorithm names to their corresponding RNDC protocol identifiers.
var (
	algosMap = map[string]int{
		"md5":    157,
		"sha1":   161,
		"sha256": 163,
		"sha384": 164,
		"sha512": 165,
	}
)

// RnDC represents an RNDC client for communicating with BIND DNS servers.
// It maintains connection state and handles message serialization/deserialization.
type RnDC struct {
	host    string
	algo    string
	secret  []byte
	ser     int64
	nonce   string
	conn    net.Conn
	once    sync.Once
	timeout time.Duration
}

// NewRNDCClient creates a new RNDC client for communicating with BIND DNS servers.
// It establishes a connection and performs the initial handshake with the server.
//
// Parameters:
//   - host: (ip, port) tuple specifying the RNDC server address
//   - algo: HMAC algorithm: one of md5, sha1, sha256, sha384, sha512
//     (with optional prefix 'hmac-')
//   - secret: HMAC secret, base64 encoded
//
// Returns:
//   - *RnDC: Initialized RNDC client
//   - error: Error if initialization fails
func NewRNDCClient(host, algo, secret string) (*RnDC, error) {
	algo = strings.ToLower(algo)
	algo = strings.TrimPrefix(algo, "hmac-")

	if _, ok := algosMap[algo]; !ok {
		supported := make([]string, 0, len(algosMap))
		for k := range algosMap {
			supported = append(supported, k)
		}
		return nil, fmt.Errorf("unsupported HMAC algorithm %q, supported: %v", algo, supported)
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 secret: %w", err)
	}

	c := &RnDC{
		host:    host,
		algo:    algo,
		secret:  decodedSecret,
		ser:     int64(rand.Intn(1 << 24)),
		timeout: 30 * time.Second,
	}

	if err := c.connectLogin(); err != nil {
		return nil, err
	}
	return c, nil
}

// connectLogin establishes a TCP connection to the RNDC server and performs
// the initial login handshake to obtain a nonce for subsequent requests.
//
// Returns:
//   - error: Error if connection or login fails
func (c *RnDC) connectLogin() error {
	var conn net.Conn
	var err error
	if c.timeout > 0 {
		conn, err = net.DialTimeout("tcp", c.host, c.timeout)
	} else {
		conn, err = net.Dial("tcp", c.host)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.host, err)
	}
	c.conn = conn
	resp, err := c.command("null")
	if err != nil {
		c.Close()
		return err
	}
	if resp.Data.Result != "0" {
		c.Close()
		return errors.New(resp.Data.Err)
	}
	c.nonce = resp.Ctrl.Nonce
	return nil
}

// command sends a command to the RNDC server and returns the response.
// It handles the complete request/response cycle including message preparation,
// transmission, and response deserialization.
//
// Parameters:
//   - cmd: The command to send to the RNDC server
//
// Returns:
//   - *CmdResponse: The response from the RNDC server
//   - error: Error if the command fails
func (c *RnDC) command(cmd string) (*CmdResponse, error) {
	msg, err := c.prepMessage(cmd)
	if err != nil {
		return nil, err
	}
	if c.timeout > 0 {
		if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			c.Close()
			return nil, fmt.Errorf("failed to set deadline on connection to %s: %w", c.host, err)
		}
	}
	sent, err := c.conn.Write(msg)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to send command %q to %s: %w", cmd, c.host, err)
	}
	if sent != len(msg) {
		c.Close()
		return nil, fmt.Errorf("partial write to %s: sent %d of %d bytes for command %q", c.host, sent, len(msg), cmd)
	}

	header := make([]byte, 8)
	_, err = io.ReadFull(c.conn, header)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to read header from %s for command %q: %w", c.host, cmd, err)
	}

	length, version, err := unpackHeader(header)
	if err != nil {
		return nil, err
	}

	if version != ProtocolVersion {
		return nil, fmt.Errorf("Protocol version mismatch, response version: %d, expected version: %d", version, ProtocolVersion)
	}

	message := make([]byte, length-4)
	_, err = io.ReadFull(c.conn, message)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to read message body (length %d) from %s for command %q: %w", length-4, c.host, cmd, err)
	}

	resp := &CmdResponse{}
	if err = resp.DeSerialize(message); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to deserialize response from %s for command %q: %w", c.host, cmd, err)
	}
	return resp, nil
}

// Call sends a command to the RNDC server and returns the response.
// This is a public wrapper around the command method.
//
// Parameters:
//   - cmd: The command to send to the RNDC server
//
// Returns:
//   - *CmdResponse: The response from the RNDC server
//   - error: Error if the command fails
func (c *RnDC) Call(cmd string) (*CmdResponse, error) {
	return c.command(cmd)
}

// prepMessage prepares an RNDC message for transmission.
// It creates the message structure, serializes it, calculates HMAC authentication,
// and adds the protocol header.
//
// Parameters:
//   - cmd: The command to include in the message
//
// Returns:
//   - []byte: The prepared message with header
//   - error: Error if message preparation fails
func (c *RnDC) prepMessage(cmd string) ([]byte, error) {
	// Prepare message structure
	ser := atomic.AddInt64(&c.ser, 1)
	now := time.Now().Unix()

	preMsg := CmdRequest{
		Ctrl: &CtrlRequest{
			Ser: strconv.FormatInt(ser, 10),
			Tim: strconv.FormatInt(now, 10),
			Exp: strconv.FormatInt(now+60, 10),
		},
		Data: &DataRequest{Type: cmd},
	}
	if c.nonce != "" {
		preMsg.Ctrl.Nonce = c.nonce
	}

	// Serialize message
	msg, err := preMsg.Serialize()
	if err != nil {
		return nil, err
	}

	// Check and calculate HMAC
	Hash, err := c.calculateHMAC(msg)
	if err != nil {
		return nil, err
	}
	bHash := make([]byte, base64.StdEncoding.EncodedLen(len(Hash)))
	base64.StdEncoding.Encode(bHash, Hash)
	authMsg, err := c.calculateAuthData(bHash)
	if err != nil {
		return nil, err
	}
	preMsg.Auth = &AuthRequest{Hash: authMsg}

	msg, err = preMsg.Serialize()
	if err != nil {
		return nil, err
	}

	return packHeader(msg)
}

// calculateHMAC calculates the HMAC signature for a message using the configured algorithm.
//
// Parameters:
//   - data: The data to calculate HMAC for
//
// Returns:
//   - []byte: The calculated HMAC signature
//   - error: Error if the algorithm is not supported
func (c *RnDC) calculateHMAC(data []byte) ([]byte, error) {
	var h func() hash.Hash

	switch c.algo {
	case "md5":
		h = md5.New
	case "sha1":
		h = sha1.New
	case "sha256":
		h = sha256.New
	case "sha384":
		h = sha512.New384
	case "sha512":
		h = sha512.New
	default:
		return nil, fmt.Errorf("HMAC algorithm %q not supported", c.algo)
	}

	ha := hmac.New(h, c.secret)
	ha.Write(data)
	return ha.Sum(nil), nil
}

// calculateAuthData prepares the authentication data for an RNDC message.
// It combines the algorithm identifier with the padded HMAC hash.
//
// Parameters:
//   - bHash: The base64-encoded HMAC hash
//
// Returns:
//   - []byte: The prepared authentication data
//   - error: Error if preparation fails
func (c *RnDC) calculateAuthData(bHash []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(byte(algosMap[c.algo]))
	bv, _ := paddingBHash(bHash)
	err := binary.Write(&buf, binary.LittleEndian, bv)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), err
}

// SetTimeout sets the connection timeout for read/write operations.
// The timeout applies to each individual network operation.
func (c *RnDC) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// Close closes the RNDC client connection and clears the secret from memory.
// It is safe to call Close multiple times.
func (c *RnDC) Close() error {
	var err error
	c.once.Do(func() {
		if c.conn != nil {
			err = c.conn.Close()
		}
		// Clear secret from memory
		if c.secret != nil {
			for i := range c.secret {
				c.secret[i] = 0
			}
			c.secret = nil
		}
	})
	return err
}

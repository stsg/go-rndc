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
	host   string
	algo   string
	secret []byte
	ser    int
	nonce  string
	conn   net.Conn
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
	rand.Seed(time.Now().UnixNano())
	c := &RnDC{
		host:   host,
		secret: []byte(secret),
		ser:    rand.Intn(1 << 24),
	}

	algo = strings.ToLower(algo)
	algo = strings.TrimPrefix(algo, "hmac-")

	switch algo {
	case "md5":
		c.algo = algo
	case "sha1":
		c.algo = algo
	case "sha256":
		c.algo = algo
	case "sha384":
		c.algo = algo
	case "sha512":
		c.algo = algo
	default:
		return nil, errors.New("unsupported HMAC algorithm")
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	c.secret = decodedSecret
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
	conn, err := net.Dial("tcp", c.host)
	if err != nil {
		return err
	}
	c.conn = conn
	resp, err := c.command("null")
	if err != nil {
		return err
	}
	if resp.Data.Result != "0" {
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
	sent, err := c.conn.Write(msg)
	if err != nil {
		return nil, err
	}
	if sent != len(msg) {
		return nil, fmt.Errorf("sent %d bytes, expected %d bytes", sent, len(msg))
	}

	header := make([]byte, 8)
	_, err = io.ReadFull(c.conn, header)
	if err != nil {
		return nil, errors.New("Read header error")
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
		return nil, fmt.Errorf("Read message error: %s", err.Error())
	}

	resp := &CmdResponse{}
	if err = resp.DeSerialize(message); err != nil {
		return nil, fmt.Errorf("DeSerialize error: %s", err.Error())
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
	c.ser++
	now := time.Now().Unix()

	preMsg := CmdRequest{
		Ctrl: &CtrlRequest{
			Ser: strconv.FormatInt(int64(c.ser), 10),
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
	Hash := c.calculateHMAC(msg)
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
func (c *RnDC) calculateHMAC(data []byte) []byte {
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
		// panic(fmt.Errorf("Algo %s not supported", c.algo))
		fmt.Printf("Algo %s not supported", c.algo)
		return nil
	}

	ha := hmac.New(h, c.secret)
	ha.Write(data)
	return ha.Sum(nil)
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

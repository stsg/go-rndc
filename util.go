package rndc

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// paddingBHash pads the given byte slice to a fixed length of 88 bytes with zeros.
// This is used to ensure consistent hash lengths in the RNDC protocol.
//
// Parameters:
//   - bHash: The byte slice to pad
//
// Returns:
//   - []byte: The padded byte slice with a length of 88 bytes
//   - error: An error if the input bHash is longer than 88 bytes
func paddingBHash(bHash []byte) ([]byte, error) {
	padLength := 88 - len(bHash)
	if padLength < 0 {
		return nil, fmt.Errorf("bHash length is too long")
	}
	bHashBytes := bHash
	bHashBytes = append(bHashBytes, bytes.Repeat([]byte{0x00}, padLength)...)
	return bHashBytes, nil
}

// unpackHeader extracts the length and version fields from the RNDC protocol header.
// The header is expected to be 8 bytes long, with the first 4 bytes representing
// the message length and the next 4 bytes representing the protocol version.
//
// Parameters:
//   - header: The 8-byte header to unpack
//
// Returns:
//   - uint32: The length of the message
//   - uint32: The protocol version
//   - error: An error if the header cannot be unpacked
func unpackHeader(header []byte) (uint32, uint32, error) {
	var length, version uint32
	err := binary.Read(bytes.NewReader(header), binary.BigEndian, &length)
	if err != nil {
		return 0, 0, fmt.Errorf("unpackHeader error: header length: %s", err.Error())
	}
	err = binary.Read(bytes.NewReader(header[4:]), binary.BigEndian, &version)
	if err != nil {
		return 0, 0, fmt.Errorf("unpackHeader error: header version: %s", err.Error())
	}
	return length, version, nil
}

// packHeader creates an RNDC protocol header for the given message.
// The header contains the message length (including 4 bytes for the length field itself)
// and the protocol version, both in big-endian format.
//
// Parameters:
//   - msg: The message to create a header for
//
// Returns:
//   - []byte: The header followed by the original message
//   - error: An error if the header cannot be created
func packHeader(msg []byte) ([]byte, error) {
	var rv bytes.Buffer
	if err := binary.Write(&rv, binary.BigEndian, uint32(len(msg)+4)); err != nil {
		return nil, fmt.Errorf("packHeader error: length: %d, error: %s", len(msg), err.Error())
	}
	if err := binary.Write(&rv, binary.BigEndian, uint32(ProtocolVersion)); err != nil {
		return nil, fmt.Errorf("packHeader error: version:%d, error: %s", ProtocolVersion, err.Error())
	}
	rv.Write(msg)
	return rv.Bytes(), nil
}

package rndc

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Serializable defines an interface for objects that can be serialized to bytes.
type Serializable interface {
	Serialize() ([]byte, error)
}

// CtrlRequest represents control information for RNDC protocol requests.
// It contains serialization metadata and timing information for request validation.
type CtrlRequest struct {
	Ser   string `json:"_ser"`             // Serial number for request tracking
	Tim   string `json:"_tim"`             // Timestamp when the request was created
	Exp   string `json:"_exp"`             // Expiration time for the request
	Nonce string `json:"_nonce,omitempty"` // Optional nonce for authentication
}

// Serialize converts the CtrlRequest into a byte array according to the RNDC protocol.
// It serializes all non-empty fields in a specific order: _ser, _tim, _exp, and optionally _nonce.
//
// Returns:
//   - []byte: The serialized byte array representation of the CtrlRequest
//   - error: Any error that occurred during serialization
func (c *CtrlRequest) Serialize() ([]byte, error) {
	var rv bytes.Buffer

	if err := serializeStringField(&rv, "_ser", c.Ser); err != nil {
		return nil, err
	}

	if err := serializeStringField(&rv, "_tim", c.Tim); err != nil {
		return nil, err
	}

	if err := serializeStringField(&rv, "_exp", c.Exp); err != nil {
		return nil, err
	}

	if c.Nonce != "" {
		if err := serializeStringField(&rv, "_nonce", c.Nonce); err != nil {
			return nil, err
		}
	}
	return rv.Bytes(), nil
}

// AuthRequest represents authentication information for RNDC protocol requests.
// It contains HMAC hash and MD5 digest for request authentication.
type AuthRequest struct {
	Hash []byte `json:"hsha,omitempty"` // HMAC hash for authentication
	Md5  []byte `json:"md5,omitempty"`  // MD5 digest (deprecated but supported)
}

// Serialize converts the AuthRequest into a byte array according to the RNDC protocol.
// It serializes the hsha field if present.
//
// Returns:
//   - []byte: The serialized byte array representation of the AuthRequest
//   - error: Any error that occurred during serialization
func (s *AuthRequest) Serialize() ([]byte, error) {
	var rv bytes.Buffer

	err := serializeBytesField(&rv, "hsha", s.Hash)
	if err != nil {
		return nil, err
	}
	return rv.Bytes(), nil
}

// CmdRequest represents a complete RNDC command request.
// It contains authentication, control, and data components of the request.
type CmdRequest struct {
	Auth *AuthRequest `json:"_auth,omitempty"` // Optional authentication information
	Ctrl *CtrlRequest `json:"_ctrl"`           // Control information for the request
	Data *DataRequest `json:"_data"`           // Data payload for the request
}

// Serialize converts the CmdRequest into a byte array according to the RNDC protocol.
// It serializes all components in a specific order: _auth (if present), _ctrl, and _data.
//
// Returns:
//   - []byte: The serialized byte array representation of the CmdRequest
//   - error: Any error that occurred during serialization
func (s *CmdRequest) Serialize() ([]byte, error) {
	var rv bytes.Buffer

	if s.Auth != nil {
		if err := serializeStructField(&rv, "_auth", s.Auth); err != nil {
			return nil, err
		}
	}

	if err := serializeStructField(&rv, "_ctrl", s.Ctrl); err != nil {
		return nil, err
	}

	if err := serializeStructField(&rv, "_data", s.Data); err != nil {
		return nil, err
	}

	return rv.Bytes(), nil
}

// DataRequest represents the data payload for an RNDC command request.
// It contains the type of command being requested.
type DataRequest struct {
	Type string `json:"type"` // The type of command being requested
}

// Serialize converts the DataRequest into a byte array according to the RNDC protocol.
// It serializes the type field.
//
// Returns:
//   - []byte: The serialized byte array representation of the DataRequest
//   - error: Any error that occurred during serialization
func (s *DataRequest) Serialize() ([]byte, error) {
	var rv bytes.Buffer

	if err := serializeStringField(&rv, "type", s.Type); err != nil {
		return nil, err
	}

	return rv.Bytes(), nil
}

// CmdResponse represents a complete RNDC command response.
// It contains authentication, control, and data components of the response.
type CmdResponse struct {
	Auth *AuthResponse `json:"_auth"` // Authentication information from the response
	Ctrl *CtrlResponse `json:"_ctrl"` // Control information from the response
	Data *DataResponse `json:"_data"` // Data payload from the response
}

// String returns a string representation of the CmdResponse for debugging purposes.
//
// Returns:
//   - string: A formatted string containing the Auth, Ctrl, and Data components
func (r *CmdResponse) String() string {
	return fmt.Sprintf("CmdResponse{Auth: %s, Ctrl: %s, Data: %s}", r.Auth, r.Ctrl, r.Data)
}

// DeSerialize parses a byte array according to the RNDC protocol and populates the CmdResponse.
// It deserializes the input data and populates the Auth, Ctrl, and Data fields as appropriate.
//
// Parameters:
//   - input: The byte array to deserialize
//
// Returns:
//   - error: Any error that occurred during deserialization
func (r *CmdResponse) DeSerialize(input []byte) error {
	pos := 0
	for pos < len(input) {
		if pos+1 > len(input) {
			return fmt.Errorf("malformed input: insufficient data for label length at position %d", pos)
		}
		labelLen := int(input[pos])
		pos++

		if pos+labelLen > len(input) {
			return fmt.Errorf("malformed input: label length %d exceeds remaining data at position %d", labelLen, pos)
		}
		label := string(input[pos : pos+labelLen])
		pos += labelLen

		if pos+1 > len(input) {
			return fmt.Errorf("malformed input: insufficient data for element type at position %d", pos)
		}
		elementType := int(input[pos])
		pos++

		if pos+4 > len(input) {
			return fmt.Errorf("malformed input: insufficient data for data length at position %d", pos)
		}
		dataLen := int(binary.BigEndian.Uint32(input[pos : pos+4]))
		if dataLen < 0 {
			return fmt.Errorf("malformed input: negative data length %d at position %d", dataLen, pos)
		}
		pos += 4

		if pos+dataLen > len(input) {
			return fmt.Errorf("malformed input: data length %d exceeds remaining data at position %d", dataLen, pos)
		}
		data := input[pos : pos+dataLen]
		pos += dataLen

		switch label {
		case "_auth":
			if r.Auth == nil {
				r.Auth = &AuthResponse{}
			}
			err := r.Auth.DeSerialize(data)
			if err != nil {
				return fmt.Errorf("failed to deserialize auth: %w", err)
			}
		case "_ctrl":
			if r.Ctrl == nil {
				r.Ctrl = &CtrlResponse{}
			}
			err := r.Ctrl.DeSerialize(data)
			if err != nil {
				return fmt.Errorf("failed to deserialize ctrl: %w", err)
			}
		case "_data":
			if r.Data == nil {
				r.Data = &DataResponse{}
			}
			err := r.Data.DeSerialize(data)
			if err != nil {
				return fmt.Errorf("failed to deserialize data: %w", err)
			}
		default:
			logger.Warn(nil, "Unknown field name: %s, field type: %d", label, elementType)
		}
	}

	return nil
}

// AuthResponse represents authentication information for RNDC protocol responses.
// It contains HMAC hash and MD5 digest from the response.
type AuthResponse struct {
	Hash []byte `json:"hsha,omitempty"` // HMAC hash from the response
	Md5  []byte `json:"md5,omitempty"`  // MD5 digest from the response
}

// String returns a string representation of the AuthResponse for debugging purposes.
//
// Returns:
//   - string: A formatted string containing the Hash and Md5 components
func (r *AuthResponse) String() string {
	return fmt.Sprintf("AuthResponse{Hash: %s, Md5: %s}", r.Hash, r.Md5)
}

// DeSerialize parses a byte array according to the RNDC protocol and populates the AuthResponse.
// It deserializes the input data and populates the Hash and Md5 fields as appropriate.
//
// Parameters:
//   - input: The byte array to deserialize
//
// Returns:
//   - error: Any error that occurred during deserialization
func (r *AuthResponse) DeSerialize(input []byte) error {
	pos := 0
	for pos < len(input) {
		if pos+1 > len(input) {
			return fmt.Errorf("malformed auth input: insufficient data for label length at position %d", pos)
		}
		labelLen := int(input[pos])
		pos++

		if pos+labelLen > len(input) {
			return fmt.Errorf("malformed auth input: label length %d exceeds remaining data at position %d", labelLen, pos)
		}
		label := string(input[pos : pos+labelLen])
		pos += labelLen

		if pos+1 > len(input) {
			return fmt.Errorf("malformed auth input: insufficient data for element type at position %d", pos)
		}
		elementType := int(input[pos])
		pos++

		if pos+4 > len(input) {
			return fmt.Errorf("malformed auth input: insufficient data for data length at position %d", pos)
		}
		dataLen := int(binary.BigEndian.Uint32(input[pos : pos+4]))
		if dataLen < 0 {
			return fmt.Errorf("malformed auth input: negative data length %d at position %d", dataLen, pos)
		}
		pos += 4

		if pos+dataLen > len(input) {
			return fmt.Errorf("malformed auth input: data length %d exceeds remaining data at position %d", dataLen, pos)
		}
		data := input[pos : pos+dataLen]
		pos += dataLen

		switch label {
		case "hsha":
			r.Hash = data
		case "md5":
			r.Md5 = data
		default:
			logger.Warn(nil, "Unknown field name: %s, field type: %d", label, elementType)
		}
	}

	return nil
}

// CtrlResponse represents control information for RNDC protocol responses.
// It contains serialization metadata and timing information from the response.
type CtrlResponse struct {
	Ser   string `json:"_ser"`             // Serial number from the response
	Tim   string `json:"_tim"`             // Timestamp when the response was created
	Exp   string `json:"_exp"`             // Expiration time from the response
	Rpl   string `json:"_rpl"`             // Reply information from the response
	Nonce string `json:"_nonce,omitempty"` // Optional nonce from the response
}

// String returns a string representation of the CtrlResponse for debugging purposes.
//
// Returns:
//   - string: A formatted string containing the Ser, Tim, Exp, Rpl, and Nonce components
func (r *CtrlResponse) String() string {
	return fmt.Sprintf("CtrlResponse{Ser: %s, Tim: %s, Exp: %s, Rpl: %s, Nonce: %s}", r.Ser, r.Tim, r.Exp, r.Rpl, r.Nonce)
}

// DeSerialize parses a byte array according to the RNDC protocol and populates the CtrlResponse.
// It deserializes the input data and populates the Ser, Tim, Exp, Rpl, and Nonce fields as appropriate.
//
// Parameters:
//   - input: The byte array to deserialize
//
// Returns:
//   - error: Any error that occurred during deserialization
func (r *CtrlResponse) DeSerialize(input []byte) error {
	pos := 0
	for pos < len(input) {
		if pos+1 > len(input) {
			return fmt.Errorf("malformed ctrl input: insufficient data for label length at position %d", pos)
		}
		labelLen := int(input[pos])
		pos++

		if pos+labelLen > len(input) {
			return fmt.Errorf("malformed ctrl input: label length %d exceeds remaining data at position %d", labelLen, pos)
		}
		label := string(input[pos : pos+labelLen])
		pos += labelLen

		if pos+1 > len(input) {
			return fmt.Errorf("malformed ctrl input: insufficient data for element type at position %d", pos)
		}
		elementType := int(input[pos])
		pos++

		if pos+4 > len(input) {
			return fmt.Errorf("malformed ctrl input: insufficient data for data length at position %d", pos)
		}
		dataLen := int(binary.BigEndian.Uint32(input[pos : pos+4]))
		if dataLen < 0 {
			return fmt.Errorf("malformed ctrl input: negative data length %d at position %d", dataLen, pos)
		}
		pos += 4

		if pos+dataLen > len(input) {
			return fmt.Errorf("malformed ctrl input: data length %d exceeds remaining data at position %d", dataLen, pos)
		}
		data := input[pos : pos+dataLen]
		pos += dataLen

		switch label {
		case "_ser":
			r.Ser = string(data)
		case "_tim":
			r.Tim = string(data)
		case "_exp":
			r.Exp = string(data)
		case "_rpl":
			r.Rpl = string(data)
		case "_nonce":
			r.Nonce = string(data)
		default:
			logger.Warn(nil, "Unknown field name: %s, field type: %d", label, elementType)
		}
	}

	return nil
}

// DataResponse represents the data payload for an RNDC command response.
// It contains the result of the command execution.
type DataResponse struct {
	Type   string `json:"type"`   // The type of response
	Result string `json:"result"` // The result code from the command execution
	Err    string `json:"err"`    // Error message if the command failed
	Text   string `json:"text"`   // Text output from the command execution
}

// String returns a string representation of the DataResponse for debugging purposes.
//
// Returns:
//   - string: A formatted string containing the Type, Result, Err, and Text components
func (r *DataResponse) String() string {
	return fmt.Sprintf("DataResponse{Type: %s, Result: %s, Err: %s, Text: %s}", r.Type, r.Result, r.Err, r.Text)
}

// DeSerialize parses a byte array according to the RNDC protocol and populates the DataResponse.
// It deserializes the input data and populates the Type, Result, Err, and Text fields as appropriate.
//
// Parameters:
//   - input: The byte array to deserialize
//
// Returns:
//   - error: Any error that occurred during deserialization
func (r *DataResponse) DeSerialize(input []byte) error {
	pos := 0
	for pos < len(input) {
		if pos+1 > len(input) {
			return fmt.Errorf("malformed data input: insufficient data for label length at position %d", pos)
		}
		labelLen := int(input[pos])
		pos++

		if pos+labelLen > len(input) {
			return fmt.Errorf("malformed data input: label length %d exceeds remaining data at position %d", labelLen, pos)
		}
		label := string(input[pos : pos+labelLen])
		pos += labelLen

		if pos+1 > len(input) {
			return fmt.Errorf("malformed data input: insufficient data for element type at position %d", pos)
		}
		elementType := int(input[pos])
		pos++

		if pos+4 > len(input) {
			return fmt.Errorf("malformed data input: insufficient data for data length at position %d", pos)
		}
		dataLen := int(binary.BigEndian.Uint32(input[pos : pos+4]))
		if dataLen < 0 {
			return fmt.Errorf("malformed data input: negative data length %d at position %d", dataLen, pos)
		}
		pos += 4

		if pos+dataLen > len(input) {
			return fmt.Errorf("malformed data input: data length %d exceeds remaining data at position %d", dataLen, pos)
		}
		data := input[pos : pos+dataLen]
		pos += dataLen

		switch label {
		case "type":
			r.Type = string(data)
		case "result":
			r.Result = string(data)
		case "err":
			r.Err = string(data)
		case "text":
			r.Text = string(data)
		default:
			logger.Warn(nil, "Unknown field name: %s, field type: %d", label, elementType)
		}
	}

	return nil
}

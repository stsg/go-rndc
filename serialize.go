package rndc

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// serializeStringField serializes a string field into the buffer according to RNDC protocol.
// The serialization format is: [key_len][key][flag][val_len][val]
// where key_len is 1 byte, flag is 1 byte (set to 1), val_len is 4 bytes (big-endian).
//
// Parameters:
//   - rv: The buffer to write the serialized data to
//   - key: The field key to serialize
//   - val: The string value to serialize
//
// Returns:
//   - error: Any error that occurred during serialization
func serializeStringField(rv *bytes.Buffer, key string, val string) error {
	// Serialize key
	// One byte stores the length of the key
	rv.WriteByte(byte(len(key)))
	// Following bytes write the key value itself
	rv.WriteString(key)

	// Serialize val
	// One byte may be a flag bit
	if err := binary.Write(rv, binary.BigEndian, uint8(1)); err != nil {
		return fmt.Errorf("serialization failed, flag bit write failed for %s field value: %s\n", key, err.Error())
	}
	// 4 bytes store the length of val, big-endian encoding (right-aligned)
	if err := binary.Write(rv, binary.BigEndian, uint32(len(val))); err != nil {
		return fmt.Errorf("serialization failed, write failed for value %s of field %s: %s\n", val, key, err.Error())
	}
	rv.WriteString(val)
	return nil
}

// serializeBytesField serializes a byte slice field into the buffer according to RNDC protocol.
// The serialization format is: [key_len][key][flag][val_len][val]
// where key_len is 1 byte, flag is 1 byte (set to 1), val_len is 4 bytes (big-endian).
//
// Parameters:
//   - rv: The buffer to write the serialized data to
//   - key: The field key to serialize
//   - val: The byte slice value to serialize
//
// Returns:
//   - error: Any error that occurred during serialization
func serializeBytesField(rv *bytes.Buffer, key string, val []byte) error {
	// Serialize key
	// One byte stores the length of the key
	rv.WriteByte(byte(len(key)))
	// Following bytes write the key value itself
	rv.WriteString(key)

	// Serialize val
	// One byte may be a flag bit
	if err := binary.Write(rv, binary.BigEndian, uint8(1)); err != nil {
		return fmt.Errorf("serialization failed, flag bit write failed for %s field value: %s\n", key, err.Error())
	}
	// 4 bytes store the length of val, big-endian encoding (right-aligned)
	if err := binary.Write(rv, binary.BigEndian, uint32(len(val))); err != nil {
		return fmt.Errorf("serialization failed, write failed for value %s of field %s: %s\n", val, key, err.Error())
	}
	rv.Write(val)
	return nil
}

// serializeStructField serializes a Serializable struct field into the buffer according to RNDC protocol.
// The serialization format is: [key_len][key][flag][val_len][val_bytes]
// where key_len is 1 byte, flag is 1 byte (set to 2 for struct), val_len is 4 bytes (big-endian).
//
// Parameters:
//   - rv: The buffer to write the serialized data to
//   - key: The field key to serialize
//   - val: The Serializable value to serialize
//
// Returns:
//   - error: Any error that occurred during serialization
func serializeStructField(rv *bytes.Buffer, key string, val Serializable) error {
	// 1. Serialize key
	// 1.1 One byte stores the length of the key
	rv.WriteByte(byte(len(key)))
	// 1.2 Following bytes write the key value itself
	rv.WriteString(key)

	// 2. Serialize val
	// 2.1 One byte may be a flag bit
	if err := binary.Write(rv, binary.BigEndian, uint8(2)); err != nil {
		return fmt.Errorf("serialization failed, flag bit write failed for %s field value: %s\n", key, err.Error())
	}
	// 2.2 Serialize the value of val
	// 2.2.1 First get the bytes of val
	valBytes, err := val.Serialize()
	if err != nil {
		return fmt.Errorf("serialization failed, write failed for value %s of field %s: %s\n", val, key, err.Error())
	}
	// 2.2.2 Store the length of val, 4 bytes store the length of val, big-endian encoding (right-aligned)
	if err := binary.Write(rv, binary.BigEndian, uint32(len(valBytes))); err != nil {
		return fmt.Errorf("serialization failed, write failed for value %s of field %s: %s\n", valBytes, key, err.Error())
	}
	// 2.2.1.3 Store the value of val
	rv.Write(valBytes)
	return nil
}

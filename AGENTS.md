# AGENTS.md - go-rndc Development Guide

This document provides guidelines for AI agents working on go-rndc, a Go RNDC (Remote Name Daemon Control) protocol library.

## Build and Development Commands

### Basic Go Commands
```bash
# Build package
go build ./...

# Run tests
go test ./...

# Run specific test
go test -v -run TestNewRNDCClient

# Test coverage
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Build example
go build ./example/client-demo
```

### Code Quality
```bash
# Format code
gofmt -w .

# Static analysis
go vet ./...
staticcheck ./...
```

## Code Style Guidelines

### Package Structure
- Package name: `rndc` (all lowercase)
- Single package in root directory
- Example code in `example/` directory

### Imports
Group imports: standard library first, alphabetical within groups:
```go
import (
    "bytes"
    "crypto/hmac"
    "crypto/md5"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "net"
    "time"
)
```

### Naming Conventions
- **Variables**: camelCase (`client`, `responseData`)
- **Constants**: PascalCase (`ProtocolVersion`)
- **Types**: PascalCase (`RnDC`, `CtrlRequest`)
- **Interfaces**: PascalCase ending with 'er' (`Serializable`)
- **Methods**: PascalCase for exported, camelCase for unexported

### Error Handling
- Check errors immediately after function calls
- Use descriptive error messages with context
- Use `fmt.Errorf()` for formatted errors

Example:
```go
func (c *RnDC) command(cmd string) (*CmdResponse, error) {
    msg, err := c.prepMessage(cmd)
    if err != nil {
        return nil, err
    }
    
    sent, err := c.conn.Write(msg)
    if err != nil {
        return nil, err
    }
    // ...
}
```

### Logging
- Use logging utilities from `logger.go`
- Log levels: Critical, Error, Warn, Info, Debug
- Set level: `rndc.SetLevelByString("error")`

### Type Definitions
- Use JSON tags for serialization fields
- Define methods on types for behavior

Example:
```go
type CtrlRequest struct {
    Ser   string `json:"_ser"`
    Tim   string `json:"_tim"`
    Exp   string `json:"_exp"`
}
```

### Comments and Documentation
- Use Chinese comments for business logic
- Use English for function documentation
- Comment precedes declaration

Example:
```go
// NewRNDCClient create rndc client
// host - (ip, port) tuple
// algo - HMAC algorithm
// secret - HMAC secret, base64 encoded
func NewRNDCClient(host, algo, secret string) (*RnDC, error) {
    // Implementation
}
```

### Testing Guidelines
- Create `_test.go` files in same package
- Use table-driven tests
- Test success and failure paths

Example:
```go
func TestNewRNDCClient(t *testing.T) {
    tests := []struct {
        name    string
        host    string
        algo    string
        secret  string
        wantErr bool
    }{
        {
            name:    "valid client",
            host:    "localhost:953",
            algo:    "hmac-sha256",
            secret:  "xRmH2XdFcDqWO91pYhiCwlZmWnaSO8EleBFu1uz8d3g=",
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            client, err := NewRNDCClient(tt.host, tt.algo, tt.secret)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Security
- Validate input parameters
- Secure HMAC secret handling
- Don't leak sensitive info in errors

### Performance
- Use buffers for serialization
- Avoid unnecessary allocations

## Current Project State

### Existing Files
- `rndc.go` - Main client and protocol logic
- `model.go` - Data structures and interfaces
- `serialize.go` - Serialization utilities
- `logger.go` - Logging utilities
- `util.go` - Utility functions
- `version.go` - Version info
- `example/client-demo/main.go` - Example

### Missing Components
1. **Tests**: No test files exist
2. **Documentation**: Minimal README
3. **Examples**: Only basic example

## Agent Instructions

When working on this codebase:
1. **Always** run `go fmt` after changes
2. **Always** run `go vet` to check issues
3. **Follow existing patterns** in codebase
4. **Add tests** for new functionality
5. **Use Chinese comments** for business logic
6. **Maintain backward compatibility** for API
7. **Handle all errors** - don't ignore them
8. **Use logging system** for debug output
9. **Check nil pointers** before dereferencing
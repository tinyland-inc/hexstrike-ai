// Package proxy manages the F*-extracted MCP server as a subprocess,
// forwarding JSON-RPC requests over stdin/stdout.
package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
)

// MCPProxy manages a subprocess running the F*-extracted MCP server.
type MCPProxy struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
	nextID int
}

// NewMCPProxy starts the MCP server binary as a subprocess.
func NewMCPProxy(binary string) (*MCPProxy, error) {
	cmd := exec.Command(binary)
	cmd.Stderr = log.Writer()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start mcp: %w", err)
	}

	p := &MCPProxy{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
		nextID: 1,
	}

	// Send initialize
	initResp, err := p.SendRequest("initialize", json.RawMessage(`{}`))
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("initialize failed: %w", err)
	}
	log.Printf("mcp initialized: %s", string(initResp))

	return p, nil
}

// jsonrpcRequest is a JSON-RPC 2.0 request.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// jsonrpcResponse is a JSON-RPC 2.0 response.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SendRequest sends a JSON-RPC request and waits for the response.
func (p *MCPProxy) SendRequest(method string, params json.RawMessage) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	id := p.nextID
	p.nextID++

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	data = append(data, '\n')
	if _, err := p.stdin.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read response line
	line, err := p.stdout.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return resp.Result, nil
}

// Alive reports whether the MCP subprocess is still running.
func (p *MCPProxy) Alive() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	// ProcessState is nil while running
	return p.cmd.ProcessState == nil
}

// Stop terminates the MCP subprocess.
func (p *MCPProxy) Stop() {
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

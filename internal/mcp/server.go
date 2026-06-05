// Package mcp serves a minimal Model Context Protocol server over stdio so an AI
// agent can vet a package (the check_package tool) before installing it. Transport
// is newline-delimited JSON-RPC 2.0 (MCP's stdio framing): one JSON object per line
// on the reader/writer; this package writes nothing to stderr.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// Checker is the seam onto the verdict engine. *check.Orchestrator satisfies it.
type Checker interface {
	CheckWith(ctx context.Context, name, version string, deep bool) verdict.Result
}

// Server serves MCP over a reader/writer.
type Server struct {
	// Resolve returns a Checker for the requested ecosystem ("npm","pypi","crates").
	Resolve func(ecosystem string) (Checker, error)
	Version string
}

const protocolVersionDefault = "2025-06-18"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests until EOF, dispatching each. Notifications (no id) get no
// response. json.Encoder.Encode appends a newline → newline-delimited output.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp, respond := s.dispatch(&req)
		if respond {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func (s *Server) dispatch(req *rpcRequest) (rpcResponse, bool) {
	isNotification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		return s.ok(req.ID, s.initializeResult(req.Params)), true
	case "notifications/initialized":
		return rpcResponse{}, false
	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": []any{checkPackageTool()}}), true
	case "tools/call":
		return s.ok(req.ID, s.toolsCall(req.Params)), true
	default:
		if isNotification {
			return rpcResponse{}, false
		}
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}, true
	}
}

func (s *Server) ok(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	pv := protocolVersionDefault
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
		pv = p.ProtocolVersion // echo the client's version (clients accept this)
	}
	return map[string]any{
		"protocolVersion": pv,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "zyrax-guard", "version": s.Version},
	}
}

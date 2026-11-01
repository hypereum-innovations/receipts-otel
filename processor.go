// SPDX-License-Identifier: Apache-2.0
// Package otelreceiptsprocessor implements a native Go OpenTelemetry Collector
// span processor for Hivemind Receipts.
//
// For every GenAI / MCP / agent action span (`gen_ai.*`, `mcp.*`, `hivemind.receipt.*`),
// the processor:
//  1. Extracts action identity, tool name, MCP method, model, and any attached receipt metadata.
//  2. Verifies an existing receipt or requests/registers a SCITT receipt against the
//     Hivemind Receipts transparency service (`ReceiptsClient`).
//  3. Enriches the span with:
//     - `hivemind.receipt.digest` (string)
//     - `hivemind.receipt.tree_size` (int64)
//     - `hivemind.receipt.verified` (bool)
//  4. In `enforce` mode, drops spans lacking a valid verified receipt; in `audit`
//     mode, retains the span while marking `hivemind.receipt.verified = false`
//     and `hivemind.receipt.audit_violation`.
package otelreceiptsprocessor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Mode controls how spans without a valid SCITT receipt are handled.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

const (
	AttrGenAIOperationName = "gen_ai.operation.name"
	AttrGenAIToolName      = "gen_ai.tool.name"
	AttrGenAISystem        = "gen_ai.system"
	AttrGenAIRequestModel  = "gen_ai.request.model"
	AttrGenAIAgentID       = "gen_ai.agent.id"
	AttrMCPMethodName      = "mcp.method.name"
	AttrMCPRequestID       = "mcp.request.id"

	AttrReceiptStatement = "hivemind.receipt.statement"
	AttrReceiptDigest    = "hivemind.receipt.digest"
	AttrReceiptTreeSize  = "hivemind.receipt.tree_size"
	AttrReceiptVerified  = "hivemind.receipt.verified"
	AttrReceiptViolation = "hivemind.receipt.audit_violation"
)

// Span represents an OpenTelemetry span within a trace batch.
type Span struct {
	TraceID      string                 `json:"trace_id"`
	SpanID       string                 `json:"span_id"`
	ParentSpanID string                 `json:"parent_span_id,omitempty"`
	Name         string                 `json:"name"`
	Status       string                 `json:"status,omitempty"` // "ok" | "error"
	Attributes   map[string]interface{} `json:"attributes"`
}

// ReceiptResponse represents the verification or issuance response from the Receipts service.
type ReceiptResponse struct {
	Digest     string `json:"digest"`
	TreeSize   int64  `json:"tree_size"`
	Verified   bool   `json:"verified"`
	Signature  string `json:"signature,omitempty"`   // base64url Ed25519 signature over canonical receipt record
	SignedData string `json:"signed_data,omitempty"` // canonical string "<digest>:<tree_size>:<trace_id>:<span_id>"
	Reason     string `json:"reason,omitempty"`
}

// IssueOrVerifyRequest is sent to the Receipts service when processing a span.
type IssueOrVerifyRequest struct {
	TraceID       string `json:"trace_id"`
	SpanID        string `json:"span_id"`
	OperationKind string `json:"operation_kind"`
	Method        string `json:"method"`
	Model         string `json:"model,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	Verdict       string `json:"verdict"`
	StatementB64  string `json:"statement_b64,omitempty"`
	ExistingDigest string `json:"existing_digest,omitempty"`
}

// ReceiptsClient abstracts communication with the Hivemind Receipts service.
type ReceiptsClient interface {
	VerifyOrIssue(ctx context.Context, req IssueOrVerifyRequest) (*ReceiptResponse, error)
}

// HTTPReceiptsClient talks to a Hivemind Receipts HTTP endpoint and optionally
// verifies an Ed25519 log signature over the returned receipt binding.
type HTTPReceiptsClient struct {
	BaseURL      string
	HTTPClient   *http.Client
	LogPublicKey ed25519.PublicKey
}

func NewHTTPReceiptsClient(baseURL string, pubKey ed25519.PublicKey) *HTTPReceiptsClient {
	return &HTTPReceiptsClient{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		LogPublicKey: pubKey,
	}
}

func (c *HTTPReceiptsClient) VerifyOrIssue(ctx context.Context, req IssueOrVerifyRequest) (*ReceiptResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/otel/verify-or-issue", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("receipts service status %d: %s", resp.StatusCode, string(respBytes))
	}

	var out ReceiptResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, err
	}

	// If a LogPublicKey is pinned, cryptographically verify the receipt signature.
	if len(c.LogPublicKey) == ed25519.PublicKeySize {
		if out.Signature == "" {
			out.Verified = false
			out.Reason = "missing_log_signature"
			return &out, nil
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(out.Signature)
		if err != nil {
			out.Verified = false
			out.Reason = "bad_signature_encoding"
			return &out, nil
		}
		canonical := out.SignedData
		if canonical == "" {
			canonical = fmt.Sprintf("%s:%d:%s:%s", out.Digest, out.TreeSize, req.TraceID, req.SpanID)
		}
		if !ed25519.Verify(c.LogPublicKey, []byte(canonical), sigBytes) {
			out.Verified = false
			out.Reason = "invalid_log_signature"
			return &out, nil
		}
	}

	return &out, nil
}

// Config configures the OTel Receipts Processor.
type Config struct {
	Mode   Mode
	Client ReceiptsClient
	// RequirePreExistingReceipt when true refuses to issue post-hoc receipts and
	// requires the span to already carry `hivemind.receipt.digest` or `hivemind.receipt.statement`.
	RequirePreExistingReceipt bool
}

// BatchSummary reports how many spans were processed, enriched, dropped, or flagged.
type BatchSummary struct {
	InputSpans    int
	KeptSpans     int
	DroppedSpans  int
	VerifiedSpans int
	FlaggedSpans  int
}

// Processor processes batches of OpenTelemetry spans.
type Processor struct {
	cfg Config
}

func NewProcessor(cfg Config) (*Processor, error) {
	if cfg.Mode != ModeEnforce && cfg.Mode != ModeAudit {
		return nil, fmt.Errorf("invalid processor mode %q: must be enforce or audit", cfg.Mode)
	}
	if cfg.Client == nil {
		return nil, errors.New("ReceiptsClient is required")
	}
	return &Processor{cfg: cfg}, nil
}

// IsAgentActionSpan determines whether a span represents a GenAI, MCP, or Hivemind receipted action.
func IsAgentActionSpan(span Span) bool {
	if span.Attributes == nil {
		return strings.HasPrefix(span.Name, "execute_tool") || strings.HasPrefix(span.Name, "mcp.")
	}
	for k := range span.Attributes {
		if strings.HasPrefix(k, "gen_ai.") || strings.HasPrefix(k, "mcp.") || strings.HasPrefix(k, "hivemind.receipt.") {
			return true
		}
	}
	return strings.HasPrefix(span.Name, "execute_tool") || strings.HasPrefix(span.Name, "invoke_agent")
}

func attrString(attrs map[string]interface{}, key string) string {
	if attrs == nil {
		return ""
	}
	v, ok := attrs[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func isValidSha256Digest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
	return err == nil
}

// ComputeSpanCommitment returns a deterministic `sha256:<hex>` digest over a span's action attributes.
func ComputeSpanCommitment(span Span) string {
	canonical := fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s",
		span.TraceID,
		span.SpanID,
		span.Name,
		attrString(span.Attributes, AttrGenAIOperationName),
		attrString(span.Attributes, AttrGenAIToolName),
		attrString(span.Attributes, AttrMCPMethodName),
	)
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ProcessBatch inspects all spans in the batch, verifies/requests SCITT receipts
// for agent action spans, enriches attributes, and drops/marks unverified spans
// according to `ModeEnforce` vs `ModeAudit`.
func (p *Processor) ProcessBatch(ctx context.Context, spans []Span) ([]Span, BatchSummary, error) {
	summary := BatchSummary{InputSpans: len(spans)}
	kept := make([]Span, 0, len(spans))

	for _, orig := range spans {
		span := orig
		if span.Attributes == nil {
			span.Attributes = make(map[string]interface{})
		}

		// Non-agent spans pass through untouched.
		if !IsAgentActionSpan(span) {
			kept = append(kept, span)
			summary.KeptSpans++
			continue
		}

		existingDigest := attrString(span.Attributes, AttrReceiptDigest)
		stmtB64 := attrString(span.Attributes, AttrReceiptStatement)

		if p.cfg.RequirePreExistingReceipt && existingDigest == "" && stmtB64 == "" {
			if p.cfg.Mode == ModeEnforce {
				summary.DroppedSpans++
				continue
			}
			span.Attributes[AttrReceiptVerified] = false
			span.Attributes[AttrReceiptDigest] = ""
			span.Attributes[AttrReceiptTreeSize] = int64(0)
			span.Attributes[AttrReceiptViolation] = "missing_receipt"
			summary.FlaggedSpans++
			summary.KeptSpans++
			kept = append(kept, span)
			continue
		}

		toolName := attrString(span.Attributes, AttrGenAIToolName)
		if toolName == "" {
			toolName = strings.TrimSpace(strings.TrimPrefix(span.Name, "execute_tool"))
		}
		mcpMethod := attrString(span.Attributes, AttrMCPMethodName)
		opKind := "tool"
		method := toolName
		if mcpMethod != "" || attrString(span.Attributes, AttrGenAISystem) == "mcp" {
			opKind = "mcp"
			if mcpMethod != "" && toolName != "" {
				method = mcpMethod + ":" + toolName
			} else if mcpMethod != "" {
				method = mcpMethod
			}
		}
		if method == "" {
			method = span.Name
		}

		verdict := "executed"
		if strings.EqualFold(span.Status, "error") {
			verdict = "errored"
		}

		req := IssueOrVerifyRequest{
			TraceID:        span.TraceID,
			SpanID:         span.SpanID,
			OperationKind:  opKind,
			Method:         method,
			Model:          attrString(span.Attributes, AttrGenAIRequestModel),
			AgentID:        attrString(span.Attributes, AttrGenAIAgentID),
			Verdict:        verdict,
			StatementB64:   stmtB64,
			ExistingDigest: existingDigest,
		}

		res, err := p.cfg.Client.VerifyOrIssue(ctx, req)
		validReceipt := err == nil && res != nil && res.Verified && isValidSha256Digest(res.Digest) && res.TreeSize > 0

		if !validReceipt {
			if p.cfg.Mode == ModeEnforce {
				summary.DroppedSpans++
				continue
			}
			reason := "unverified_receipt"
			if err != nil {
				reason = err.Error()
			} else if res != nil && res.Reason != "" {
				reason = res.Reason
			}
			span.Attributes[AttrReceiptVerified] = false
			if res != nil && res.Digest != "" {
				span.Attributes[AttrReceiptDigest] = res.Digest
				span.Attributes[AttrReceiptTreeSize] = res.TreeSize
			} else {
				span.Attributes[AttrReceiptDigest] = existingDigest
				span.Attributes[AttrReceiptTreeSize] = int64(0)
			}
			span.Attributes[AttrReceiptViolation] = reason
			summary.FlaggedSpans++
			summary.KeptSpans++
			kept = append(kept, span)
			continue
		}

		span.Attributes[AttrReceiptDigest] = res.Digest
		span.Attributes[AttrReceiptTreeSize] = res.TreeSize
		span.Attributes[AttrReceiptVerified] = true
		delete(span.Attributes, AttrReceiptViolation)

		summary.VerifiedSpans++
		summary.KeptSpans++
		kept = append(kept, span)
	}

	return kept, summary, nil
}

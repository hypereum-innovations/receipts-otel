// SPDX-License-Identifier: Apache-2.0
package otelreceiptsprocessor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func startFakeReceiptsServer(t *testing.T, priv ed25519.PrivateKey, treeSize int64, tamperSig bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/otel/verify-or-issue" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req IssueOrVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ExistingDigest == "sha256:bad" {
			_ = json.NewEncoder(w).Encode(ReceiptResponse{
				Digest:   req.ExistingDigest,
				TreeSize: treeSize,
				Verified: false,
				Reason:   "digest_not_found_in_log",
			})
			return
		}
		digest := req.ExistingDigest
		if digest == "" {
			digest = ComputeSpanCommitment(Span{
				TraceID: req.TraceID,
				SpanID:  req.SpanID,
				Name:    req.Method,
				Attributes: map[string]interface{}{
					AttrGenAIToolName: req.Method,
				},
			})
		}
		canonical := fmt.Sprintf("%s:%d:%s:%s", digest, treeSize, req.TraceID, req.SpanID)
		sig := ed25519.Sign(priv, []byte(canonical))
		if tamperSig {
			sig[0] ^= 0xff
		}
		_ = json.NewEncoder(w).Encode(ReceiptResponse{
			Digest:     digest,
			TreeSize:   treeSize,
			Verified:   true,
			SignedData: canonical,
			Signature:  base64.RawURLEncoding.EncodeToString(sig),
		})
	}))
}

func TestProcessorEnforceModeEnrichesAndDropsInvalid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := startFakeReceiptsServer(t, priv, 42, false)
	defer srv.Close()

	client := NewHTTPReceiptsClient(srv.URL, pub)
	proc, err := NewProcessor(Config{
		Mode:   ModeEnforce,
		Client: client,
	})
	if err != nil {
		t.Fatalf("new processor: %v", err)
	}

	spans := []Span{
		{
			TraceID: "trace-1",
			SpanID:  "span-genai-ok",
			Name:    "execute_tool refund_invoice",
			Status:  "ok",
			Attributes: map[string]interface{}{
				AttrGenAIOperationName: "execute_tool",
				AttrGenAIToolName:      "refund_invoice",
				AttrGenAIRequestModel:  "claude-4-sonnet",
				AttrGenAIAgentID:       "spiffe://hivemind.example/agent/billing",
			},
		},
		{
			TraceID: "trace-1",
			SpanID:  "span-mcp-bad",
			Name:    "mcp.tools.call",
			Status:  "ok",
			Attributes: map[string]interface{}{
				AttrMCPMethodName: "tools/call",
				AttrGenAIToolName: "delete_database",
				AttrReceiptDigest: "sha256:bad",
			},
		},
		{
			TraceID: "trace-1",
			SpanID:  "span-http-passthrough",
			Name:    "GET /healthz",
			Attributes: map[string]interface{}{
				"http.method": "GET",
			},
		},
	}

	kept, summary, err := proc.ProcessBatch(context.Background(), spans)
	if err != nil {
		t.Fatalf("process batch: %v", err)
	}

	if summary.InputSpans != 3 || summary.KeptSpans != 2 || summary.DroppedSpans != 1 || summary.VerifiedSpans != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept spans, got %d", len(kept))
	}

	enriched := kept[0]
	if enriched.SpanID != "span-genai-ok" {
		t.Fatalf("unexpected first span: %s", enriched.SpanID)
	}
	if enriched.Attributes[AttrReceiptVerified] != true {
		t.Fatalf("expected hivemind.receipt.verified=true, got %v", enriched.Attributes[AttrReceiptVerified])
	}
	if enriched.Attributes[AttrReceiptTreeSize] != int64(42) {
		t.Fatalf("expected tree_size=42, got %v", enriched.Attributes[AttrReceiptTreeSize])
	}
	digestStr, _ := enriched.Attributes[AttrReceiptDigest].(string)
	if !isValidSha256Digest(digestStr) {
		t.Fatalf("expected valid sha256 digest, got %q", digestStr)
	}
}

func TestProcessorAuditModeMarksUnverifiedWithoutDropping(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Tamper signature so verification fails
	srv := startFakeReceiptsServer(t, priv, 19, true)
	defer srv.Close()

	client := NewHTTPReceiptsClient(srv.URL, pub)
	proc, err := NewProcessor(Config{
		Mode:                      ModeAudit,
		Client:                    client,
		RequirePreExistingReceipt: false,
	})
	if err != nil {
		t.Fatalf("new processor: %v", err)
	}

	spans := []Span{
		{
			TraceID: "trace-audit-1",
			SpanID:  "span-audit-1",
			Name:    "execute_tool send_email",
			Attributes: map[string]interface{}{
				AttrGenAIOperationName: "execute_tool",
				AttrGenAIToolName:      "send_email",
			},
		},
	}

	kept, summary, err := proc.ProcessBatch(context.Background(), spans)
	if err != nil {
		t.Fatalf("process batch: %v", err)
	}
	if summary.DroppedSpans != 0 || summary.FlaggedSpans != 1 || len(kept) != 1 {
		t.Fatalf("unexpected audit summary: %+v", summary)
	}
	if kept[0].Attributes[AttrReceiptVerified] != false {
		t.Fatalf("expected verified=false in audit mode, got %v", kept[0].Attributes[AttrReceiptVerified])
	}
	if kept[0].Attributes[AttrReceiptViolation] != "invalid_log_signature" {
		t.Fatalf("expected violation=invalid_log_signature, got %v", kept[0].Attributes[AttrReceiptViolation])
	}
}

func TestProcessorRequirePreExistingReceiptEnforceVsAudit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := startFakeReceiptsServer(t, priv, 100, false)
	defer srv.Close()

	client := NewHTTPReceiptsClient(srv.URL, pub)
	enforceProc, _ := NewProcessor(Config{
		Mode:                      ModeEnforce,
		Client:                    client,
		RequirePreExistingReceipt: true,
	})
	auditProc, _ := NewProcessor(Config{
		Mode:                      ModeAudit,
		Client:                    client,
		RequirePreExistingReceipt: true,
	})

	spanWithoutReceipt := Span{
		TraceID: "trace-missing",
		SpanID:  "span-missing",
		Name:    "execute_tool query_db",
		Attributes: map[string]interface{}{
			AttrGenAIOperationName: "execute_tool",
			AttrGenAIToolName:      "query_db",
		},
	}

	keptEnforce, sumEnforce, _ := enforceProc.ProcessBatch(context.Background(), []Span{spanWithoutReceipt})
	if len(keptEnforce) != 0 || sumEnforce.DroppedSpans != 1 {
		t.Fatalf("expected enforce mode to drop span without pre-existing receipt, got %+v", sumEnforce)
	}

	keptAudit, sumAudit, _ := auditProc.ProcessBatch(context.Background(), []Span{spanWithoutReceipt})
	if len(keptAudit) != 1 || sumAudit.FlaggedSpans != 1 {
		t.Fatalf("expected audit mode to keep and flag span without pre-existing receipt, got %+v", sumAudit)
	}
	if keptAudit[0].Attributes[AttrReceiptViolation] != "missing_receipt" {
		t.Fatalf("expected missing_receipt violation, got %v", keptAudit[0].Attributes[AttrReceiptViolation])
	}
}

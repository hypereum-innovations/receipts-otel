// SPDX-License-Identifier: Apache-2.0
/**
 * OTLP/HTTP receiver that turns GenAI spans into capsules (zero-code capture
 * where teams are already instrumented). Parses the OTLP JSON encoding
 * (resourceSpans/scopeSpans/spans with anyValue attributes), maps
 * execute_tool/invoke_agent spans through `otelSpanToAction`, authorizes is
 * not possible post-hoc — spans describe completed actions — so verdicts are
 * recorded faithfully and the decision reference is the "observed" marker.
 * Run: tsx src/receipts/integrations/otel-processor.ts (PORT 4319).
 */
import Fastify from 'fastify';
import { otelSpanToAction, OTEL_RECEIPT_ATTRIBUTE } from './surface-helpers.js';
import type { ReceiptCapture } from './capture.js';
import type { AuthZenResponse } from '../authz/authzen-types.js';

export interface OtlpJson {
  resourceSpans?: Array<{
    scopeSpans?: Array<{
      spans?: OtlpSpan[];
    }>;
  }>;
}

export interface OtlpSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  attributes?: Array<{ key: string; value: { stringValue?: string; intValue?: string | number; boolValue?: boolean } }>;
  status?: { code?: number };
}

export function flattenAttributes(span: OtlpSpan): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const attr of span.attributes ?? []) {
    const v = attr.value;
    if (typeof v.stringValue === 'string') out[attr.key] = v.stringValue;
    else if (v.intValue !== undefined) out[attr.key] = Number(v.intValue);
    else if (typeof v.boolValue === 'boolean') out[attr.key] = v.boolValue;
  }
  return out;
}

const OBSERVED_DECISION: AuthZenResponse = {
  decision: true,
  hivemind: {
    decision_digest: 'observed-post-hoc',
    policy_set_digest: 'n/a',
    reasons: ['recorded from telemetry after execution; no pre-authorization took place on this surface'],
    requires_approval: false,
  },
};

export async function processOtlp(
  payload: OtlpJson,
  capture: ReceiptCapture,
): Promise<{ recorded: number; receiptIds: string[] }> {
  const receiptIds: string[] = [];
  for (const rs of payload.resourceSpans ?? []) {
    for (const ss of rs.scopeSpans ?? []) {
      for (const span of ss.spans ?? []) {
        const mapped = otelSpanToAction({
          trace_id: span.traceId,
          span_id: span.spanId,
          name: span.name,
          attributes: flattenAttributes(span),
          ...(span.status?.code === 2 ? { status: 'error' as const } : { status: 'ok' as const }),
          ...(span.parentSpanId ? { parent_span_id: span.parentSpanId } : {}),
        });
        if (!mapped) continue;
        const receipt = await capture.record(mapped.action, mapped.verdict, OBSERVED_DECISION, mapped.observed);
        receiptIds.push(receipt.capsule.capsule_id);
      }
    }
  }
  return { recorded: receiptIds.length, receiptIds };
}

export function buildOtelProcessor(capture: ReceiptCapture) {
  const app = Fastify({ logger: false });
  app.post('/v1/traces', async (req) => processOtlp(req.body as OtlpJson, capture));
  app.get('/health', async () => ({ ok: true, surface: 'otel->receipts', span_link_attribute: OTEL_RECEIPT_ATTRIBUTE }));
  return app;
}

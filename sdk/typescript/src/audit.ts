/**
 * Audit events (`client.audit`), mirroring `sandfort_sdk.audit`: list, page through, ask the
 * server to verify the hash chain, and export the events as newline-delimited JSON lines.
 */

import type { LineSource } from "./audit-continuation.js";
import { exportLines, type ExportRequest } from "./audit-export.js";
import {
  exportResult,
  type ExportVerification,
  type VerifyExportOptions,
} from "./audit-export-verify.js";
import {
  NO_STATUS_KEY,
  STATUS_KEY,
  checkExpectedOrg,
  parseHead,
  verifyHead,
  type HeadRecord,
  type HeadVerification,
  type VerifyHeadOptions,
} from "./audit-head.js";
import { scanExport } from "./audit-scan.js";
import {
  auditEventFromPayload,
  verifyResultFromPayload,
  type AuditEvent,
  type AuditVerifyResult,
} from "./audit-models.js";
import { ValidationError } from "./errors.js";
import { pageFromPayload, type Page } from "./models.js";
import { paginate, type Cursor } from "./pagination.js";
import { callArgs, type CallOptions } from "./resilience.js";
import { STATUS_PATH, statusFromPayload } from "./status.js";
import type { Query, Transport } from "./transport.js";
import { momentIso, requireListLimit, requireOptionalNonBlank } from "./validation.js";

export const AUDIT_PATH = "/v1/audit-events";
export const AUDIT_VERIFY_PATH = "/v1/audit-events/verify";
export const AUDIT_ORDERS = ["asc", "desc"] as const;
export type AuditOrder = (typeof AUDIT_ORDERS)[number];

export interface AuditExportFilters extends ExportRequest {
  requestId?: string;
  outcome?: string;
  /** Both ends are `Date`s; the request carries them as UTC. */
  from?: Date;
  to?: Date;
}

export interface ListAuditOptions extends CallOptions {
  actorId?: string;
  action?: string;
  targetId?: string;
  requestId?: string;
  outcome?: string;
  from?: Date;
  to?: Date;
  /** Sort by id: `asc` (default, oldest first) or `desc`; page on with the same order. */
  order?: AuditOrder;
  /** A page's `nextCursor`, passed back as is (`null` and `undefined` start at the first page). */
  cursor?: Cursor;
  /** 1 to 100 (server default 50). */
  limit?: number;
}

/** Filters for `listAll`: the same on every page, so no cursor. */
export type ListAuditFilters = Omit<ListAuditOptions, "cursor">;

export interface VerifyAuditOptions extends CallOptions {
  /** Start the walk at this event instead of the first. */
  fromId?: string;
}

/** A trusted public key (text or the 32 raw bytes), or `"status"` to read it from `GET /v1/status`. */
export type TrustedKey = string | Uint8Array;

function moment(value: Date | undefined, label: string): string | undefined {
  return value === undefined ? undefined : momentIso(value, label);
}

function auditListQuery(options: ListAuditOptions): Query {
  const { order } = options;
  if (order !== undefined && !AUDIT_ORDERS.includes(order)) {
    throw new ValidationError(
      `order must be one of ${AUDIT_ORDERS.join(", ")}; got ${JSON.stringify(order)}`,
    );
  }
  requireListLimit(options.limit);
  const cursor = options.cursor ?? undefined;
  const named = {
    actor_id: options.actorId,
    action: options.action,
    target_id: options.targetId,
    request_id: options.requestId,
    outcome: options.outcome,
    cursor,
  };
  for (const [label, value] of Object.entries(named)) requireOptionalNonBlank(value, label);
  return {
    ...named,
    from: moment(options.from, "from"),
    to: moment(options.to, "to"),
    order,
    limit: options.limit,
  };
}

function auditExportQuery(filters: AuditExportFilters): Query {
  requireOptionalNonBlank(filters.requestId, "requestId");
  requireOptionalNonBlank(filters.outcome, "outcome");
  return {
    from: moment(filters.from, "from"),
    to: moment(filters.to, "to"),
    request_id: filters.requestId,
    outcome: filters.outcome,
  };
}

export class Audit {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /** One page of events; page on with `cursor: page.nextCursor` and the same `order`. */
  async list(options: ListAuditOptions = {}): Promise<Page<AuditEvent>> {
    const reply = await this.#transport.requestEnvelope("GET", AUDIT_PATH, {
      query: auditListQuery(options),
      ...callArgs(options),
    });
    return pageFromPayload(reply.data, reply.nextCursor, auditEventFromPayload);
  }

  /** Every event matching `filters`, page by page with the same filters each time. */
  listAll(filters: ListAuditFilters = {}): AsyncGenerator<AuditEvent, void, undefined> {
    return paginate((cursor) => this.list({ ...filters, cursor }));
  }

  /**
   * Ask the server to walk the org's hash chain (all rows, or from `fromId`). This is the
   * full check; a client cannot recompute the keyed row hashes.
   */
  async verifyChain(options: VerifyAuditOptions = {}): Promise<AuditVerifyResult> {
    requireOptionalNonBlank(options.fromId, "fromId");
    const reply = await this.#transport.request("GET", AUDIT_VERIFY_PATH, {
      query: { from_id: options.fromId },
      ...callArgs(options),
    });
    return verifyResultFromPayload(reply);
  }

  /**
   * The export body line by line as it arrives, each line with its `\n` (the last one may lack
   * it). Filters are checked now; the request is sent on the first read. A broken or aborted
   * stream raises `TransportError` / `RequestAbortedError`; lines already read stay valid.
   */
  exportLines(filters: AuditExportFilters = {}): AsyncGenerator<string, void, undefined> {
    const query = auditExportQuery(filters);
    return exportLines(this.#transport, query, filters);
  }

  /**
   * The audit public key the server publishes on `GET /v1/status` (no key needed), or `null`
   * while it signs no heads. Pin it out of band when you can: a key read from the server you are
   * auditing is only as trustworthy as that connection.
   */
  async publicKey(call: CallOptions = {}): Promise<string | null> {
    const reply = await this.#transport.request("GET", STATUS_PATH, { ...callArgs(call) });
    return statusFromPayload(reply).auditPublicKey || null;
  }

  /**
   * Check the Ed25519 signature of an export's `audit_head` trailer line (see `verifyHead`).
   * `publicKey` is the trust anchor, or `"status"` to read it from `GET /v1/status` (one request,
   * made only for that value, and only after the line parsed). Throws `ValidationError` when the
   * server publishes no key. `expectedOrgId` makes a signed head of another org fail with
   * `"expected_org_mismatch"`; an empty one throws `ValidationError` before any request.
   */
  async verifyHead(
    headLine: string | HeadRecord,
    publicKey: TrustedKey,
    options: VerifyHeadOptions & CallOptions = {},
  ): Promise<HeadVerification> {
    if (publicKey !== STATUS_KEY) return verifyHead(headLine, publicKey, options);
    parseHead(headLine); // a bad line fails before any request
    checkExpectedOrg(options.expectedOrgId); // before the status request
    return verifyHead(headLine, await this.#statusKey(options), options);
  }

  /**
   * Check an export against its signed trailer (see `verifyExport`). `lines` is the whole body or
   * its lines, e.g. `client.audit.exportLines()`. `publicKey` is the trust anchor, or `"status"`
   * to read it from `GET /v1/status` once the file has been read.
   */
  async verifyExport(
    lines: LineSource,
    publicKey: TrustedKey,
    options: VerifyExportOptions & CallOptions = {},
  ): Promise<ExportVerification> {
    checkExpectedOrg(options.expectedOrgId);
    const scan = await scanExport(lines, options.previous ?? null);
    const key = publicKey === STATUS_KEY ? await this.#statusKey(options) : publicKey;
    return exportResult(scan, key, options.allowUnchained ?? false, options.expectedOrgId);
  }

  async #statusKey(call: CallOptions): Promise<string> {
    const key = await this.publicKey(call);
    if (key === null) throw new ValidationError(NO_STATUS_KEY);
    return key;
  }
}

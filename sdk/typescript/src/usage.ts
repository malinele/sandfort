/**
 * Usage report (`client.usage`), mirroring `sandfort_sdk.usage`: metered resource totals of
 * the org for a period. Without `groupBy` the answer is the org totals; with it, a page of
 * groups (one per sandbox, or one per value of a label key) and the cursor of the next page.
 * An API key limited to labelled sandboxes sees only the sandboxes that carry all its labels.
 */

import { InvalidResponseError } from "./errors.js";
import { asArray, asRecord, requiredString, stringOrNull, type Page } from "./models.js";
import { paginate } from "./pagination.js";
import { callArgs, type CallOptions } from "./resilience.js";
import type { Transport } from "./transport.js";
import { fail, momentIso, requireListLimit, requireNonBlank } from "./validation.js";

export const USAGE_PATH = "/v1/org/usage";
const GROUP_BY_SANDBOX = "sandbox";
const GROUP_BY_LABEL_PREFIX = "label:";
const GROUP_BY_HELP = "'sandbox' or 'label:<key>'";

/**
 * One dimension of the report (`vcpu`, `memory_mib`, `disk_gib`) with its unit. Both stay
 * plain strings so that a value a newer server adds still loads as sent.
 */
export interface UsageTotal {
  dimension: string;
  unit: string;
  total: number;
}

/**
 * One group of a grouped report. For `groupBy: "sandbox"` `groupValue` is the sandbox id and
 * `name` and `labels` are the sandbox's at report time. For `label:<key>` `groupKey` is that
 * and `groupValue` the label value, `null` for sandboxes without that label.
 */
export interface UsageGroup {
  groupKey: string;
  groupValue: string | null;
  totals: readonly UsageTotal[];
  name: string | null;
  labels: Record<string, string> | null;
}

/** One answer: `totals` without `groupBy`; `groups` and `nextCursor` with it. */
export interface UsageReport {
  totals: readonly UsageTotal[];
  groups: readonly UsageGroup[];
  nextCursor: string | null;
}

export interface UsagePeriod {
  /** Start of the period (a `Date`, sent as UTC). */
  from: Date;
  to: Date;
}

export interface GetUsageOptions extends UsagePeriod, CallOptions {
  /** `"sandbox"` or `"label:<key>"`; without it the answer is the org totals. */
  groupBy?: string;
  /** `nextCursor` of the previous page of the same period and `groupBy`; needs `groupBy`. */
  cursor?: string | null | undefined;
  /** Groups per page, 1 to 100 (server default 50); needs `groupBy`. */
  limit?: number;
}

/** Options of `groupsAll`: a period and a `groupBy` are both required, there is no cursor. */
export interface IterateUsageOptions extends UsagePeriod, CallOptions {
  groupBy: string;
  limit?: number;
}

function totalFromPayload(data: unknown): UsageTotal {
  const raw = asRecord(data, "usage total");
  const total = raw["total"];
  if (typeof total !== "number") {
    throw new InvalidResponseError("expected a number for usage total");
  }
  return {
    dimension: requiredString(raw, "dimension", "usage total"),
    unit: requiredString(raw, "unit", "usage total"),
    total,
  };
}

function totalsFromPayload(data: unknown): UsageTotal[] {
  return asArray(data, "usage totals").map(totalFromPayload);
}

function labelsOrNull(value: unknown): Record<string, string> | null {
  if (value === undefined || value === null) return null;
  const raw = asRecord(value, "usage group labels");
  const entries = Object.entries(raw);
  if (!entries.every(([, item]) => typeof item === "string")) {
    throw new InvalidResponseError("usage group labels must map strings to strings");
  }
  return Object.fromEntries(entries) as Record<string, string>;
}

function groupFromPayload(data: unknown): UsageGroup {
  const raw = asRecord(data, "usage group");
  if (!("group_value" in raw)) {
    throw new InvalidResponseError("usage group payload is missing 'group_value'");
  }
  return {
    groupKey: requiredString(raw, "group_key", "usage group"),
    groupValue: stringOrNull(raw["group_value"]),
    totals: totalsFromPayload(raw["totals"]),
    name: stringOrNull(raw["name"]),
    labels: labelsOrNull(raw["labels"]),
  };
}

function checkGroupBy(value: string): string {
  const key = value.slice(GROUP_BY_LABEL_PREFIX.length);
  const isLabel = value.startsWith(GROUP_BY_LABEL_PREFIX) && key.trim() !== "";
  if (value === GROUP_BY_SANDBOX || isLabel) return value;
  return fail(`groupBy must be ${GROUP_BY_HELP}; got ${JSON.stringify(value)}`);
}

/** The query of a report call; every failure is a `ValidationError` raised before sending. */
function usageQuery(options: GetUsageOptions): Record<string, string | number | undefined> {
  const query = {
    from: momentIso(options.from, "from"),
    to: momentIso(options.to, "to"),
  };
  const cursor = options.cursor ?? undefined;
  if (options.groupBy === undefined) {
    if (cursor !== undefined || options.limit !== undefined) {
      fail("'cursor' and 'limit' need 'groupBy'");
    }
    return query;
  }
  if (cursor !== undefined) requireNonBlank(cursor, "cursor");
  requireListLimit(options.limit);
  return { ...query, group_by: checkGroupBy(options.groupBy), cursor, limit: options.limit };
}

export class Usage {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /** The report for `from`..`to`: org totals, or with `groupBy` one page of groups. */
  async get(options: GetUsageOptions): Promise<UsageReport> {
    const reply = await this.#transport.requestEnvelope("GET", USAGE_PATH, {
      query: usageQuery(options),
      ...callArgs(options),
    });
    if (options.groupBy === undefined) {
      return { totals: totalsFromPayload(reply.data), groups: [], nextCursor: null };
    }
    const items = asArray(reply.data, "usage groups").map(groupFromPayload);
    return { totals: [], groups: items, nextCursor: reply.nextCursor };
  }

  /**
   * Every group of a grouped report, page by page with the same period, `groupBy` and
   * `limit`. The cursor is internal: it needs an explicit period. A server that repeats a
   * cursor would loop forever, so that raises `InvalidResponseError`.
   */
  groupsAll(options: IterateUsageOptions): AsyncGenerator<UsageGroup, void, undefined> {
    return paginate(async (cursor): Promise<Page<UsageGroup>> => {
      if (options.groupBy === undefined) fail(`groupsAll needs 'groupBy': ${GROUP_BY_HELP}`);
      const report = await this.get({ ...options, cursor });
      return { items: report.groups, nextCursor: report.nextCursor };
    });
  }
}

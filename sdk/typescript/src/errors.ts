/** Error hierarchy mirroring `sandfort_sdk.exceptions` for what travels on the wire. */

export class SandfortError extends Error {
  /** `options.cause` carries the error this one wraps (a fetch failure, an abort reason). */
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** `message` with the server's request id appended, when there is one (for support lookups). */
export function withRequestId(message: string, requestId: string | null | undefined): string {
  return requestId === undefined || requestId === null || requestId === ""
    ? message
    : `${message} (request id ${requestId})`;
}

/** The request never produced a response (connect failure, DNS, abort, ...). */
export class TransportError extends SandfortError {}

/** A request failed client-side validation; nothing was sent. */
export class ValidationError extends SandfortError {}

/** The request ran past the client's `timeoutMs` before the server answered. */
export class RequestTimeoutError extends TransportError {}

/** The caller's `AbortSignal` fired before the request finished. */
export class RequestAbortedError extends TransportError {}

/** A successful HTTP response did not carry the expected envelope or payload. */
export class InvalidResponseError extends SandfortError {}

/** The sandbox did not reach `started` within the wait budget. */
export class SandboxTimeoutError extends SandfortError {}

/** The sandbox settled in a state that can never become `started`. */
export class SandboxFailedError extends SandfortError {
  readonly sandboxId: string;
  readonly state: string;

  constructor(message: string, sandboxId: string, state: string) {
    super(message);
    this.sandboxId = sandboxId;
    this.state = state;
  }
}

export interface ApiErrorInit {
  code?: string | undefined;
  status?: number | undefined;
  details?: Record<string, unknown> | undefined;
  requestId?: string | undefined;
}

/** An error envelope returned by the server; subclasses map known statuses and codes. */
export class ApiError extends SandfortError {
  readonly code: string;
  readonly status: number | undefined;
  readonly details: Readonly<Record<string, unknown>>;
  readonly requestId: string | undefined;

  constructor(message: string, init: ApiErrorInit = {}) {
    super(message);
    this.code = init.code ?? "API_ERROR";
    this.status = init.status;
    this.details = init.details ?? {};
    this.requestId = init.requestId;
  }
}

export class ValidationFailed extends ApiError {}
export class Unauthorized extends ApiError {}
export class Forbidden extends ApiError {}
export class NotFound extends ApiError {}
export class Conflict extends ApiError {}
export class InvalidState extends Conflict {}

export class RateLimited extends ApiError {
  readonly retryAfterS: number;

  constructor(message: string, init: ApiErrorInit = {}, retryAfterS = 1) {
    super(message, init);
    this.retryAfterS = retryAfterS;
  }
}

type ApiErrorClass = new (message: string, init?: ApiErrorInit) => ApiError;

// Maps, not plain objects: a server code such as "constructor" or "__proto__" must not find an
// inherited property and come back as a non-error.
const BY_CODE: ReadonlyMap<string, ApiErrorClass> = new Map<string, ApiErrorClass>([
  ["VALIDATION_ERROR", ValidationFailed],
  ["UNPROCESSABLE", ValidationFailed],
  ["UNAUTHORIZED", Unauthorized],
  ["FORBIDDEN", Forbidden],
  ["NOT_FOUND", NotFound],
  ["CONFLICT", Conflict],
  ["INVALID_STATE", InvalidState],
  ["RATE_LIMITED", RateLimited],
]);

const BY_STATUS: ReadonlyMap<number, ApiErrorClass> = new Map<number, ApiErrorClass>([
  [400, ValidationFailed],
  [401, Unauthorized],
  [403, Forbidden],
  [404, NotFound],
  [409, Conflict],
  [422, ValidationFailed],
  [429, RateLimited],
]);

export interface ErrorFor {
  code: string | undefined;
  message: string;
  status: number | undefined;
  details?: Record<string, unknown> | undefined;
  requestId?: string | undefined;
  retryAfterS?: number | undefined;
}

/** Pick the subclass by envelope code first, then by HTTP status; `ApiError` if unknown. */
export function errorFor(input: ErrorFor): ApiError {
  const init: ApiErrorInit = {
    code: input.code,
    status: input.status,
    details: input.details,
    requestId: input.requestId,
  };
  const byCode = input.code === undefined ? undefined : BY_CODE.get(input.code);
  const byStatus = input.status === undefined ? undefined : BY_STATUS.get(input.status);
  const cls = byCode ?? byStatus ?? ApiError;
  if (cls === RateLimited) {
    return new RateLimited(input.message, init, input.retryAfterS ?? 1);
  }
  return new cls(input.message, init);
}

/**
 * Cursor pagination. A page carries `nextCursor` (`null` on the last page); the next request
 * passes it back with the same filters, which the server checks (a changed filter answers 422).
 */

import { InvalidResponseError } from "./errors.js";
import type { Page } from "./models.js";

/** What a list call accepts as `cursor`: a `nextCursor` may be passed back as it came. */
export type Cursor = string | null | undefined;

/**
 * Yield every item of a list, page after page, until `nextCursor` is `null`.
 * `fetchPage` must apply the same filters to each call; a server that repeats a cursor
 * would loop forever, so that is reported as an invalid response.
 */
export async function* paginate<T>(
  fetchPage: (cursor: string | undefined) => Promise<Page<T>>,
): AsyncGenerator<T, void, undefined> {
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (;;) {
    const page = await fetchPage(cursor);
    yield* page.items;
    if (page.nextCursor === null) return;
    if (seen.has(page.nextCursor)) {
      throw new InvalidResponseError("the server returned a cursor it had already returned");
    }
    seen.add(page.nextCursor);
    cursor = page.nextCursor;
  }
}

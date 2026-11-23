import { describe, expect, it } from "vitest";
import { InvalidResponseError, type FollowLogEvent } from "../src/index.js";
import { at, clientFor, type QueueItem, type Recorded } from "./helpers.js";
import { sse } from "./contexts-helpers.js";

const LINES = ["alpha\n", "bb\n", "c\n", "dddd\n"];
const FINAL_SIZE = LINES.join("").length;

function frame(event: string, data: unknown, id?: number): string {
  const idLine = id === undefined ? "" : `id: ${id}\n`;
  return `${idLine}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/** A server that sends one event per line from the requested offset, like the real one. */
function followFrom(request: Recorded): Response {
  const url = new URL(request.url);
  const start = Number(url.searchParams.get("offset") ?? request.headers.get("last-event-id") ?? 0);
  const chunks: string[] = [];
  let position = 0;
  for (const line of LINES) {
    const end = position + line.length;
    if (position >= start) {
      chunks.push(frame("stdout", { stream: "stdout", offset: position, line }, end));
    }
    position = end;
  }
  chunks.push(frame("exit", { exit_code: 0, state: "exited", truncated: false }, FINAL_SIZE));
  return sse(chunks);
}

const lineOf = (event: FollowLogEvent): string => (event.type === "exit" ? "" : event.line);

describe("followCommandLogs resume", () => {
  it("continues after the last seen event: no line twice, none missing", async () => {
    const { client, requests } = clientFor([followFrom, followFrom]);
    const seen: string[] = [];
    let resumeAt: number | null = null;

    for await (const event of client.followCommandLogs("sbx_1", "s1", "c1")) {
      seen.push(lineOf(event));
      if (seen.length === 2) {
        resumeAt = event.nextOffset;
        break;
      }
    }
    expect(resumeAt).toBe(LINES[0]!.length + LINES[1]!.length);
    const options = { offset: resumeAt as number };
    const rest: FollowLogEvent[] = [];
    for await (const event of client.followCommandLogs("sbx_1", "s1", "c1", options)) {
      rest.push(event);
    }

    expect(at(requests, 1).url).toContain(`offset=${String(resumeAt)}`);
    expect([...seen, ...rest.map(lineOf)].filter(Boolean)).toEqual(LINES);
    expect(rest.at(-1)).toMatchObject({ type: "exit", nextOffset: FINAL_SIZE });
  });

  it("chains nextOffset through every event of a whole run", async () => {
    const { client } = clientFor([followFrom]);
    const events: FollowLogEvent[] = [];

    for await (const event of client.followCommandLogs("sbx_1", "s1", "c1")) events.push(event);

    const starts = events.flatMap((event) => (event.type === "exit" ? [] : [event.offset]));
    const ends = events.slice(0, -1).map((event) => event.nextOffset);
    expect(starts).toEqual([0, ...ends.slice(0, -1)]);
    expect(ends.at(-1)).toBe(FINAL_SIZE);
  });

  it("refuses an event id that is not a byte offset", async () => {
    const bad: QueueItem = sse([
      "id: abc\nevent: stdout\ndata: " +
        JSON.stringify({ stream: "stdout", offset: 0, line: "x\n" }) +
        "\n\n",
    ]);
    const { client } = clientFor([bad]);

    const run = client.followCommandLogs("sbx_1", "s1", "c1").next();

    await expect(run).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

import { describe, expect, it } from "vitest";
import { InvalidResponseError } from "../src/index.js";
import { MAX_PENDING_CHARS, SseDecoder, type SseFrame } from "../src/sse.js";

const encoder = new TextEncoder();

function bytes(text: string): Uint8Array {
  return encoder.encode(text);
}

function decodeAll(chunks: readonly (string | Uint8Array)[]): SseFrame[] {
  const decoder = new SseDecoder();
  const frames: SseFrame[] = [];
  for (const chunk of chunks) {
    frames.push(...decoder.feed(typeof chunk === "string" ? bytes(chunk) : chunk));
  }
  frames.push(...decoder.end());
  return frames;
}

describe("SseDecoder", () => {
  it("joins multi-line data with newlines", () => {
    const frames = decodeAll(["event: out\ndata: a\ndata: b\ndata:\ndata: c\n\n"]);

    expect(frames).toEqual([{ event: "out", data: "a\nb\n\nc" }]);
  });

  it("strips one leading space of a value and no more", () => {
    const frames = decodeAll(["data:  two\n\ndata:none\n\n"]);

    expect(frames.map((f) => f.data)).toEqual([" two", "none"]);
  });

  it("ignores retry lines and comments and keeps the id of the frame", () => {
    const frames = decodeAll([": keep-alive\nid: 7\nretry: 1000\nevent: x\ndata: 1\n\n"]);

    expect(frames).toEqual([{ event: "x", data: "1", id: "7" }]);
  });

  it("gives each frame its own id and none to a frame without one", () => {
    const frames = decodeAll(["id: 5\ndata: a\n\ndata: b\n\nid:9\ndata: c\n\n"]);

    expect(frames).toEqual([
      { event: "message", data: "a", id: "5" },
      { event: "message", data: "b" },
      { event: "message", data: "c", id: "9" },
    ]);
  });

  it("keeps an id split across chunks and ignores one that holds a NUL", () => {
    const frames = decodeAll(["id: 1", "2\ndata: a\n\nid: 1\u00002\ndata: b\n\n"]);

    expect(frames).toEqual([
      { event: "message", data: "a", id: "12" },
      { event: "message", data: "b" },
    ]);
  });

  it("drops a leading byte order mark", () => {
    const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
    const first = Uint8Array.from([...bom, ...bytes("data: hi\n\n")]);

    expect(decodeAll([first])).toEqual([{ event: "message", data: "hi" }]);
  });

  it("drops a byte order mark split across chunks", () => {
    const frames = decodeAll([Uint8Array.of(0xef, 0xbb), Uint8Array.of(0xbf, 0x64), "ata: hi\n\n"]);

    expect(frames).toEqual([{ event: "message", data: "hi" }]);
  });

  it("flushes a final event that has no trailing blank line", () => {
    const frames = decodeAll(["event: result\ndata: {}\n"]);

    expect(frames).toEqual([{ event: "result", data: "{}" }]);
  });

  it("flushes a final line that has no line end at all", () => {
    expect(decodeAll(["data: tail"])).toEqual([{ event: "message", data: "tail" }]);
  });

  it("reads a CR at a chunk boundary as a line end and swallows the LF that follows", () => {
    const decoder = new SseDecoder();

    expect(decoder.feed(bytes("data: a\r"))).toEqual([]);
    expect(decoder.feed(bytes("\ndata: b\r\n\r"))).toEqual([{ event: "message", data: "a\nb" }]);
    expect(decoder.feed(bytes("\n"))).toEqual([]);
    expect(decoder.feed(bytes("data: c\n\n"))).toEqual([{ event: "message", data: "c" }]);
  });

  it("does not mistake a CR before a blank line for part of a CRLF", () => {
    const decoder = new SseDecoder();

    expect(decoder.feed(bytes("data: a\r"))).toEqual([]);
    expect(decoder.feed(bytes("\rdata: b\r\r"))).toEqual([
      { event: "message", data: "a" },
      { event: "message", data: "b" },
    ]);
  });

  it("reads a lone CR followed by another character as a line end", () => {
    const frames = decodeAll(["data: a\r", "\rdata: b\r\r"]);

    expect(frames).toEqual([
      { event: "message", data: "a" },
      { event: "message", data: "b" },
    ]);
  });

  it("flushes the event of a stream that ends right after a CR", () => {
    expect(decodeAll(["data: a\r"])).toEqual([{ event: "message", data: "a" }]);
  });

  it("keeps a multi-byte character split across chunks", () => {
    const all = bytes("data: café\n\n");
    const frames = decodeAll([all.slice(0, 10), all.slice(10)]);

    expect(frames).toEqual([{ event: "message", data: "café" }]);
  });

  it("completes a character left half-sent when the stream ends", () => {
    const all = bytes("data: é");
    const frames = decodeAll([all.slice(0, all.length - 1), all.slice(all.length - 1)]);

    expect(frames).toEqual([{ event: "message", data: "é" }]);
  });

  it("raises InvalidResponseError for an overlong line", () => {
    const decoder = new SseDecoder();

    expect(() => decoder.feed(bytes(`data: ${"x".repeat(MAX_PENDING_CHARS)}`))).toThrow(
      InvalidResponseError,
    );
  });

  it("raises InvalidResponseError when a line grows past the cap over many chunks", () => {
    const decoder = new SseDecoder();
    const piece = bytes("x".repeat(1 << 20));
    const feedAll = (): void => {
      for (let i = 0; i < 10; i += 1) decoder.feed(piece);
    };

    expect(feedAll).toThrow(InvalidResponseError);
  });

  it("raises InvalidResponseError when the data of one event passes the cap", () => {
    const decoder = new SseDecoder();
    const line = bytes(`data: ${"y".repeat((1 << 20) - 7)}\n`);
    const feedAll = (): void => {
      for (let i = 0; i < 10; i += 1) decoder.feed(line);
    };

    expect(feedAll).toThrow(InvalidResponseError);
  });

  it("accepts many events that together pass the cap", () => {
    const decoder = new SseDecoder();
    const event = bytes(`data: ${"z".repeat((1 << 20) - 8)}\n\n`);
    let seen = 0;

    for (let i = 0; i < 12; i += 1) seen += decoder.feed(event).length;

    expect(seen).toBe(12);
  });

  it("scans only newly fed text, so a long line fed in tiny pieces stays fast", () => {
    const decoder = new SseDecoder();
    const piece = bytes("a".repeat(64));
    const started = Date.now();

    for (let i = 0; i < 20_000; i += 1) decoder.feed(piece);
    const frames = decoder.feed(bytes("\n\n"));

    expect(frames).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("parses many short lines of one chunk without rescanning", () => {
    const decoder = new SseDecoder();
    const text = "data: x\n\n".repeat(100_000);

    expect(decoder.feed(bytes(text))).toHaveLength(100_000);
  });
});

/**
 * Incremental decoder for a server-sent-events byte stream (`event`, `data` and `id` fields).
 * Memory is bounded: one pending line, and the data of one pending event, may each hold at
 * most `MAX_PENDING_CHARS` characters; beyond that `InvalidResponseError` is raised. Each fed
 * chunk is scanned once, so the cost is linear in the stream, however it is split.
 */

import { InvalidResponseError } from "./errors.js";

export interface SseFrame {
  /** The `event:` field; `"message"` when the frame has none. */
  event: string;
  /** The `data:` lines of the frame joined with `\n`. */
  data: string;
  /** The `id:` field of the frame, as sent; absent when the frame has none. */
  id?: string;
}

/** About 8 MiB of text: the cap on a pending line and on the pending data of one event. */
export const MAX_PENDING_CHARS = 8 * 1024 * 1024;

const DEFAULT_EVENT = "message";
const LF = 10;
const CR = 13;

function lineTooLong(): InvalidResponseError {
  return new InvalidResponseError(
    `an event-stream line is longer than ${MAX_PENDING_CHARS} characters`,
  );
}

export class SseDecoder {
  readonly #text = new TextDecoder();
  /** The pieces of the line being received, without its line end (joined once it is whole). */
  #parts: string[] = [];
  #partsChars = 0;
  /** The last chunk ended with a CR: an LF at the start of the next one belongs to it. */
  #skipLf = false;
  #event = "";
  #id: string | undefined;
  #data: string[] = [];
  #dataChars = 0;

  /** Add the next chunk of bytes; returns the frames it completed. */
  feed(chunk: Uint8Array): SseFrame[] {
    return this.#process(this.#text.decode(chunk, { stream: true }));
  }

  /**
   * Call once the byte stream has ended: flushes the text decoder, treats a last line without
   * a line end as complete and returns the frames that gives, including an event that was
   * not closed by a blank line.
   */
  end(): SseFrame[] {
    const frames = this.#process(this.#text.decode());
    if (this.#parts.length > 0) this.#push(frames, this.#consume(this.#takeLine("")));
    this.#push(frames, this.#dispatch());
    return frames;
  }

  #push(frames: SseFrame[], frame: SseFrame | undefined): void {
    if (frame !== undefined) frames.push(frame);
  }

  /** Consume the lines of `text`, a piece of the stream, looking at each character once. */
  #process(text: string): SseFrame[] {
    const frames: SseFrame[] = [];
    let start = this.#skipLf && text.charCodeAt(0) === LF ? 1 : 0;
    this.#skipLf = false;
    for (let index = start; index < text.length; index += 1) {
      const code = text.charCodeAt(index);
      if (code !== LF && code !== CR) continue;
      const line = this.#takeLine(text.slice(start, index));
      start = index + 1;
      if (code === CR) {
        // CR LF is one line end, even when the LF arrives in the next chunk.
        if (start === text.length) this.#skipLf = true;
        else if (text.charCodeAt(start) === LF) {
          index += 1;
          start += 1;
        }
      }
      this.#push(frames, this.#consume(line));
    }
    this.#keep(text.slice(start));
    return frames;
  }

  /** The whole line that `tail` ends: the pieces kept so far plus `tail`. */
  #takeLine(tail: string): string {
    const parts = this.#parts;
    const line = parts.length === 0 ? tail : parts.join("") + tail;
    this.#parts = [];
    this.#partsChars = 0;
    if (line.length > MAX_PENDING_CHARS) throw lineTooLong();
    return line;
  }

  /** Remember the unfinished start of the next line. */
  #keep(piece: string): void {
    if (piece === "") return;
    this.#partsChars += piece.length;
    if (this.#partsChars > MAX_PENDING_CHARS) throw lineTooLong();
    this.#parts.push(piece);
  }

  #consume(line: string): SseFrame | undefined {
    if (line === "") return this.#dispatch();
    if (line.startsWith(":")) return undefined;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const raw = colon === -1 ? "" : line.slice(colon + 1);
    const value = raw.startsWith(" ") ? raw.slice(1) : raw;
    if (field === "event") this.#event = value;
    else if (field === "data") this.#addData(value);
    else if (field === "id" && !value.includes("\0")) this.#id = value;
    return undefined;
  }

  #addData(value: string): void {
    this.#dataChars += value.length + 1;
    if (this.#dataChars > MAX_PENDING_CHARS) {
      throw new InvalidResponseError(
        `the data of one event-stream event is longer than ${MAX_PENDING_CHARS} characters`,
      );
    }
    this.#data.push(value);
  }

  #dispatch(): SseFrame | undefined {
    const data = this.#data;
    const event = this.#event;
    const id = this.#id;
    this.#id = undefined;
    this.#data = [];
    this.#dataChars = 0;
    this.#event = "";
    if (data.length === 0) return undefined;
    const frame: SseFrame = { event: event === "" ? DEFAULT_EVENT : event, data: data.join("\n") };
    return id === undefined ? frame : { ...frame, id };
  }
}

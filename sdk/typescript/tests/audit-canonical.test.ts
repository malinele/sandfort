import { describe, expect, it } from "vitest";
import {
  CanonicalError,
  canonicalJson,
  decodeBase64Url,
  encodeBase64Url,
} from "../src/audit-canonical.js";

// Expected strings are the output of python's
// json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).
describe("canonicalJson matches python's json.dumps", () => {
  it("sorts keys by code point (an astral key sorts after U+FFEE, unlike UTF-16 order)", () => {
    const value = { b: 1, a: [true, false, null, "x"], "\u{1F600}": 1, "￮": 2, z: { y: 0, x: -5 } };

    expect(canonicalJson(value)).toBe(
      '{"a":[true,false,null,"x"],"b":1,"z":{"x":-5,"y":0},"\\uffee":2,"\\ud83d\\ude00":1}',
    );
  });

  it("escapes controls, DEL, non-ASCII, astral pairs and lone surrogates in lowercase hex", () => {
    const text = 'tab\t nl\n cr\r bs\b ff\f q" bk\\ del\x7f ctl\x01\x1f é   \u{10437} \ud800 end';

    expect(canonicalJson({ s: text })).toBe(
      '{"s":"tab\\t nl\\n cr\\r bs\\b ff\\f q\\" bk\\\\ del\\u007f ctl\\u0001\\u001f \\u00e9 \\u2028 \\ud801\\udc37 \\ud800 end"}',
    );
  });

  it("writes empty keys and values", () => {
    expect(canonicalJson({ "": "" })).toBe('{"":""}');
  });

  it("refuses what it cannot reproduce byte for byte", () => {
    for (const bad of [1.5, 2 ** 60, Number.NaN, undefined, () => 1, 10n]) {
      expect(() => canonicalJson({ x: bad })).toThrow(CanonicalError);
    }
    expect(() => canonicalJson(JSON.parse(`${"[".repeat(100)}${"]".repeat(100)}`))).toThrow(/too deeply/);
  });
});

describe("urlsafe base64", () => {
  it("round-trips with padding and decodes without it", () => {
    const raw = new Uint8Array([251, 255, 190, 1, 2]);

    expect(encodeBase64Url(raw)).toBe("-_--AQI=");
    expect([...(decodeBase64Url("-_--AQI=") ?? [])]).toEqual([...raw]);
    expect([...(decodeBase64Url("-_--AQI") ?? [])]).toEqual([...raw]);
  });

  it("rejects standard-alphabet characters, stray padding and impossible lengths", () => {
    for (const bad of ["+/+/", "AA=A", "A", "AAAAA", "AA==AA==", "a b"]) {
      expect(decodeBase64Url(bad), bad).toBeNull();
    }
  });
});

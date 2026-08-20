import { describe, expect, it } from "vitest";
import { jcsSerialize } from "../src/core/jcs.js";

describe("JCS (RFC 8785)", () => {
  it("sorts object keys and strips whitespace", () => {
    expect(jcsSerialize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("keeps array order (never reorders)", () => {
    expect(jcsSerialize({ arr: ["b", "a"] })).toBe('{"arr":["b","a"]}');
  });

  it("nested objects are canonicalized recursively", () => {
    expect(jcsSerialize({ z: { y: 1, x: 2 }, a: [{ c: 3, b: 4 }] })).toBe(
      '{"a":[{"b":4,"c":3}],"z":{"x":2,"y":1}}',
    );
  });

  it("escapes strings like JSON.stringify (RFC 8785 string rules)", () => {
    expect(jcsSerialize({ s: 'a"b\n\x07' })).toBe('{"s":"a\\"b\\n\\u0007"}');
  });

  it("sorts keys by UTF-16 code units (RFC 8785 section 3.2.3 example)", () => {
    const input: Record<string, string> = {};
    input["\u20ac"] = "Euro Sign";
    input["\r"] = "Carriage Return";
    input["\ufb33"] = "Hebrew Letter Dalet With Dagesh";
    input["1"] = "One";
    input["\ud83d\ude00"] = "Emoji: Grinning Face";
    input["\u0080"] = "Control";
    input["\u00f6"] = "Latin Small Letter O With Diaeresis";
    // The emoji (surrogate pair D83D DE00) sorts BEFORE U+FB33 — UTF-16 code units, not code points.
    const expected =
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}';
    expect(jcsSerialize(input)).toBe(expected);
  });

  it("rejects undefined and non-finite numbers", () => {
    expect(() => jcsSerialize(undefined)).toThrow();
    expect(() => jcsSerialize({ n: Infinity })).toThrow();
  });

  it("serializes numbers the ECMAScript way", () => {
    expect(jcsSerialize({ n: 10, f: 1.5, z: 0 })).toBe('{"f":1.5,"n":10,"z":0}');
  });
});

import { describe, it, expect, beforeEach } from "vitest";
import { recordSequence, checkSequence, clearSequenceState } from "../../src/v3/sequence-state";

beforeEach(() => clearSequenceState());

describe("sequence-state", () => {
  it("accepts first observation", () => {
    expect(checkSequence("t.example", 1).rollback).toBe(false);
    recordSequence("t.example", 1);
  });

  it("accepts monotonically-increasing sequence", () => {
    recordSequence("t.example", 1);
    expect(checkSequence("t.example", 2).rollback).toBe(false);
    recordSequence("t.example", 2);
  });

  it("flags rollback when seeing lower sequence than recorded", () => {
    recordSequence("t.example", 5);
    const r = checkSequence("t.example", 3);
    expect(r.rollback).toBe(true);
    expect(r.highestSeen).toBe(5);
    expect(r.received).toBe(3);
  });

  it("isolates state per domain", () => {
    recordSequence("a.example", 10);
    expect(checkSequence("b.example", 1).rollback).toBe(false);
  });
});

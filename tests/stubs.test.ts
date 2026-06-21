import { describe, expect, it } from "vitest";
import { parseFileContent } from "../src/core/parse-diff.js";
import { stubsDetector } from "../src/detectors/stubs.js";

const run = (path: string, content: string) =>
  stubsDetector.run({
    files: [parseFileContent(path, content)],
    options: { cwd: process.cwd() },
  });

describe("stubs detector", () => {
  it("flags TODO markers", () => {
    const r = run("a.ts", "// TODO: implement this\nconst x = 1;");
    expect(r.findings.some((f) => f.id === "stub:todo")).toBe(true);
  });

  it("flags FIXME markers", () => {
    const r = run("a.ts", "// FIXME later");
    expect(r.findings.some((f) => f.id === "stub:todo")).toBe(true);
  });

  it("flags throw new Error('not implemented') in TS", () => {
    const r = run("a.ts", "function f() { throw new Error('not implemented'); }");
    const f = r.findings.find((x) => x.id === "stub:not_implemented");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("flags Python NotImplementedError", () => {
    const r = run("a.py", "def f():\n    raise NotImplementedError");
    expect(r.findings.some((f) => f.id === "stub:not_implemented")).toBe(true);
  });

  it("flags Rust todo!()", () => {
    const r = run("a.rs", "fn f() { todo!() }");
    expect(r.findings.some((f) => f.id === "stub:not_implemented")).toBe(true);
  });

  it("flags bare pass in Python", () => {
    const r = run("a.py", "def f():\n    pass");
    expect(r.findings.some((f) => f.id === "stub:pass_only")).toBe(true);
  });

  it("flags dummy/placeholder returns", () => {
    const r = run("a.ts", "return dummy_value;");
    expect(r.findings.some((f) => f.id === "stub:dummy_return")).toBe(true);
  });

  it("does NOT flag stub patterns inside comments (other than TODO)", () => {
    const r = run("a.ts", "// throws not implemented somewhere");
    expect(r.findings.some((f) => f.id === "stub:not_implemented")).toBe(false);
  });
});

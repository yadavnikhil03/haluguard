import { describe, expect, it } from "vitest";
import { detectLanguage } from "../src/core/language.js";
import { parseDiff, parseFileContent } from "../src/core/parse-diff.js";

describe("detectLanguage", () => {
  it("maps common extensions", () => {
    expect(detectLanguage("foo.ts")).toBe("typescript");
    expect(detectLanguage("foo.tsx")).toBe("tsx");
    expect(detectLanguage("foo.mjs")).toBe("javascript");
    expect(detectLanguage("foo.py")).toBe("python");
    expect(detectLanguage("foo.go")).toBe("go");
    expect(detectLanguage("foo.rs")).toBe("rust");
    expect(detectLanguage("Makefile")).toBe("unknown");
  });

  it("is case-insensitive", () => {
    expect(detectLanguage("FOO.PY")).toBe("python");
  });
});

describe("parseDiff", () => {
  it("extracts added lines from a git-style diff with correct new-file line numbers", () => {
    const diff = [
      "diff --git a/src/a.ts b/src/a.ts",
      "index 0000000..1111111 100644",
      "--- a/src/a.ts",
      "+++ b/src/a.ts",
      "@@ -1,3 +1,4 @@",
      " context line one",
      " context line two",
      "+added line three",
      " context line four",
      "+added line five",
    ].join("\n");

    const files = parseDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0].path).toBe("src/a.ts");
    expect(files[0].language).toBe("typescript");

    expect(files[0].addedLines.map((l) => [l.lineNumber, l.text])).toEqual([
      [3, "added line three"],
      [5, "added line five"],
    ]);
  });

  it("handles multiple files in one diff", () => {
    const diff = [
      "diff --git a/a.py b/a.py",
      "--- a/a.py",
      "+++ b/a.py",
      "@@ -1,1 +1,1 @@",
      "+x = 1",
      "diff --git a/b.ts b/b.ts",
      "--- b/b.ts",
      "+++ b/b.ts",
      "@@ -1,1 +1,2 @@",
      " ctx",
      "+y = 2",
    ].join("\n");

    const files = parseDiff(diff);
    expect(files.map((f) => f.path)).toEqual(["a.py", "b.ts"]);
  });

  it("ignores removed lines but still tracks context for line numbering", () => {
    const diff = ["--- a/x.ts", "+++ b/x.ts", "@@ -5,3 +5,3 @@", "-removed", "+added", " ctx"].join(
      "\n",
    );
    const files = parseDiff(diff);
    expect(files[0].addedLines).toEqual([{ lineNumber: 5, text: "added" }]);
  });

  it("treats /dev/null new-file headers gracefully", () => {
    const diff = ["--- a/deleted.ts", "+++ /dev/null", "@@ -1,1 +0,0 @@", "-gone"].join("\n");
    expect(parseDiff(diff)).toEqual([]);
  });
});

describe("parseFileContent", () => {
  it("treats every line as added with 1-based numbering", () => {
    const file = parseFileContent("app.ts", "a\nb\nc");
    expect(file.addedLines.map((l) => l.lineNumber)).toEqual([1, 2, 3]);
    expect(file.newContent).toBe("a\nb\nc");
  });
});

import { describe, expect, it } from "vitest";
import { parseFileContent } from "../src/core/parse-diff.js";
import { secretsDetector } from "../src/detectors/secrets.js";
import type { FileChange } from "../src/types.js";

const run = (path: string, content: string) =>
  secretsDetector.run({
    files: [parseFileContent(path, content)],
    options: { cwd: process.cwd() },
  });

describe("secrets detector", () => {
  it("flags an AWS access key id", () => {
    const r = run("a.ts", `const key = "AKIAIOSFODNN7EXAMPLE";`);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe("secret:aws_access_key_id");
    expect(r.findings[0].severity).toBe("high");
  });

  it("flags a GitHub PAT", () => {
    const r = run("a.ts", `token = "ghp_" + "A".repeat(36)`);

    const real = "ghp_1234567890abcdefghij1234567890abcdefghij";
    const r2 = run("a.ts", `token = "${real}"`);
    expect(r2.findings.some((f) => f.id === "secret:github_pat")).toBe(true);
  });

  it("flags an OpenAI key", () => {
    const r = run("a.ts", `openai_api_key = "sk-" + "abcd".repeat(8)`);
    const r2 = run("a.ts", `key = "sk-${"a".repeat(30)}"`);
    expect(r2.findings.some((f) => f.id === "secret:openai_api_key")).toBe(true);
  });

  it("flags a private key block as critical", () => {
    const r = run("a.ts", `const k = "-----BEGIN RSA PRIVATE KEY-----"`);
    const f = r.findings.find((x) => x.id === "secret:private_key_block");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("flags a generic high-entropy secret assignment", () => {
    const longToken = "x9K2vqM7nT3pL8wR5sY1bH4dF6jC0gU0AbC";
    const r = run("a.ts", `api_key = "${longToken}"`);
    expect(r.findings.some((f) => f.id === "secret:generic_high_entropy")).toBe(true);
  });

  it("ignores placeholders like your_key_here", () => {
    const r = run("a.ts", `api_key = "your_api_key_here_abcdef1234567890abcdef"`);
    expect(r.findings.filter((f) => f.id === "secret:generic_high_entropy")).toHaveLength(0);
  });

  it("skips secrets written in comments", () => {
    const r = run("a.ts", `// const key = "AKIAIOSFODNN7EXAMPLE";`);
    expect(r.findings).toHaveLength(0);
  });

  it("skips secrets in Python comments", () => {
    const r = run("a.py", `# openai_key = "sk-${"a".repeat(30)}"`);
    expect(r.findings).toHaveLength(0);
  });

  it("redacts the snippet in the finding so reports are shareable", () => {
    const r = run("a.ts", `k = "AKIAIOSFODNN7EXAMPLE"`);
    const snippet = r.findings[0].snippet;
    expect(snippet).toContain("AKIA");
    expect(snippet).toContain("*");
    expect(snippet).not.toContain("EXAMPLE");
  });
});

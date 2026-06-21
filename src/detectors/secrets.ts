import type { DiffLine, Finding } from "../types.js";
import type { Detector, DetectorContext } from "./registry.js";

interface Signature {
  id: string;
  title: string;
  pattern: RegExp;

  minEntropy?: number;
}

const SIGNATURES: Signature[] = [
  {
    id: "aws_access_key_id",
    title: "AWS Access Key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws_secret",
    title: "AWS Secret Access Key",
    pattern:
      /\b(Aws_secret_access_key|aws_secret_access_key|awsSecret)["':\s=]+["']([A-Za-z0-9/+=]{40})["']/g,
    minEntropy: 3.5,
  },
  {
    id: "github_pat",
    title: "GitHub Personal Access Token",
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: "google_api_key",
    title: "Google API Key",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    id: "openai_api_key",
    title: "OpenAI API Key",
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "anthropic_api_key",
    title: "Anthropic API Key",
    pattern: /\bsk-ant-[A-Za-z0-9_\-]{50,}\b/g,
  },
  {
    id: "stripe_key",
    title: "Stripe Secret Key",
    pattern: /\bsk_(live|test)_[0-9a-zA-Z]{24,}\b/g,
  },
  {
    id: "slack_token",
    title: "Slack Token",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    id: "jwt",
    title: "Hardcoded JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: "private_key_block",
    title: "Private Key Block",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
];

const GENERIC_TOKEN =
  /(?:api[_-]?key|apikey|token|secret|passwd|password|auth[_-]?token|access[_-]?token)\s*[=:]\s*["']([A-Za-z0-9+/_\-=]{32,})["']/gi;

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const GENERIC_MIN_ENTROPY = 4.0;
const GENERIC_MIN_LENGTH = 32;

function isLikelyPlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  if (v.includes("<") || v.includes("${")) return true;

  if (
    v.startsWith("your") ||
    v.startsWith("xxx") ||
    v.startsWith("changeme") ||
    v.startsWith("placeholder") ||
    v.startsWith("redacted") ||
    v.startsWith("example") ||
    v.startsWith("sample") ||
    v.startsWith("dummy") ||
    v.startsWith("fake") ||
    v.startsWith("lorem") ||
    (v.startsWith("foo") && /^[a-z]+$/.test(v.slice(3))) ||
    (v.startsWith("bar") && /^[a-z]+$/.test(v.slice(3))) ||
    (v.startsWith("test") && /^[a-z]+$/.test(v.slice(4)))
  ) {
    return true;
  }
  return false;
}

function detectInFile(path: string, addedLines: DiffLine[]): Finding[] {
  const findings: Finding[] = [];

  for (const { lineNumber, text } of addedLines) {
    const trimmed = text.trim();
    if (
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("*") ||
      trimmed.startsWith("/*")
    ) {
      continue;
    }

    for (const sig of SIGNATURES) {
      sig.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic regex match loop
      while ((m = sig.pattern.exec(text)) !== null) {
        const matched = m[0];
        if (sig.minEntropy !== undefined) {
          const captured = m[2] ?? matched;
          if (shannonEntropy(captured) < sig.minEntropy) continue;
        }
        findings.push(buildFinding(sig.id, sig.title, path, lineNumber, matched));
      }
    }

    GENERIC_TOKEN.lastIndex = 0;
    let gm: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic regex match loop
    while ((gm = GENERIC_TOKEN.exec(text)) !== null) {
      const value = gm[1];
      if (value.length < GENERIC_MIN_LENGTH) continue;
      if (isLikelyPlaceholder(value)) continue;
      if (shannonEntropy(value) < GENERIC_MIN_ENTROPY) continue;
      findings.push(
        buildFinding(
          "generic_high_entropy",
          `Possible hardcoded secret (${shannonEntropy(value).toFixed(1)} bits/char)`,
          path,
          lineNumber,
          value,
        ),
      );
    }
  }

  return findings;
}

function buildFinding(
  sigId: string,
  title: string,
  file: string,
  line: number,
  snippet: string,
): Finding {
  return {
    id: `secret:${sigId}`,
    category: "secret",
    severity: sigId === "private_key_block" ? "critical" : "high",
    detector: "secrets",
    title,
    message: `This line appears to contain a ${title}. Rotate it immediately and move it to a secret manager / environment variable. AI assistants frequently paste real credentials into diffs — always review added lines for secrets before merging.`,
    location: { file, startLine: line, endLine: line },
    snippet: redact(snippet),
  };
}

function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 6, 24))}${value.slice(-2)}`;
}

export const secretsDetector: Detector = {
  id: "secrets",
  name: "Leaked Secrets",
  run(ctx: DetectorContext) {
    const start = Date.now();
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      findings.push(...detectInFile(file.path, file.addedLines));
    }
    return { detector: "secrets", findings, durationMs: Date.now() - start };
  },
};

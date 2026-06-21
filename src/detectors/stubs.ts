import type { DiffLine, FileLanguage, Finding } from "../types.js";
import type { Detector, DetectorContext } from "./registry.js";

interface StubRule {
  id: string;

  patterns: Partial<Record<FileLanguage | "all", RegExp[]>>;
  severity: Finding["severity"];
  title: string;
  message: string;
}

const ALL: FileLanguage | "all" = "all";

const RULES: StubRule[] = [
  {
    id: "todo",
    patterns: { [ALL]: [/\b(TODO|FIXME|XXX|HACK|todo!)\b/i] },
    severity: "info",
    title: "Leftover TODO/FIXME marker",
    message:
      "This line ships a TODO/FIXME that was likely written by an AI assistant as scaffolding. Either resolve it before merge or convert to a tracked issue.",
  },
  {
    id: "not_implemented",
    patterns: {
      typescript: [/throw\s+new\s+Error\(["']not implemented/i, /throw\s+new\s+Error\(["']TODO/i],
      javascript: [/throw\s+new\s+Error\(["']not implemented/i, /throw\s+new\s+Error\(["']TODO/i],
      tsx: [/throw\s+new\s+Error\(["']not implemented/i],
      jsx: [/throw\s+new\s+Error\(["']not implemented/i],
      python: [/raise\s+NotImplementedError/, /raise\s+Exception\(["']not implemented/i],
      go: [/panic\(["']not implemented/i],
      rust: [/(?:todo!|unimplemented!)\s*\(/],
      java: [/throw\s+new\s+UnsupportedOperationException\(/],
      csharp: [/throw\s+new\s+NotImplementedException\(/],
    },
    severity: "medium",
    title: "Stubbed implementation throws at runtime",
    message:
      "This added code throws/aborts when reached. AI assistants often leave these as placeholders and they're easy to miss in review. Wire up the real implementation or guard the call site.",
  },
  {
    id: "pass_only",
    patterns: { python: [/^\s*pass\s*$/] },
    severity: "low",
    title: "Empty function body (pass)",
    message:
      "Function reduced to a bare `pass`. Likely a scaffolded stub. Confirm it's intentional (e.g. abstract method) or implement it.",
  },
  {
    id: "ellipsis_body",
    patterns: {
      typescript: [/^\s*(?:\.\.\.|return\s+(?:null|undefined)\s*;?\s*$)/, /^\s*\{\s*\}$/],
      javascript: [/^\s*(?:\.\.\.|return\s+(?:null|undefined)\s*;?\s*$)/, /^\s*\{\s*\}$/],
      python: [/^\s*\.\.\.\s*$/],
    },
    severity: "low",
    title: "Empty / placeholder body",
    message:
      "Function or block body is empty or returns null/undefined. Often left behind by an AI scaffold. Implement it or document why it's intentionally empty.",
  },
  {
    id: "dummy_return",
    patterns: { [ALL]: [/\b(?:dummy|placeholder|fake|stub)[_\s]+(?:value|data|return)/i] },
    severity: "low",
    title: "Dummy / placeholder return value",
    message:
      "Line references a dummy/placeholder value. Make sure no real code path depends on this in production.",
  },
];

const COMMENT_PREFIXES = new Set(["//", "#", "*", "/*", "<!--"]);

function isCommentLine(text: string): boolean {
  const t = text.trim();
  for (const p of COMMENT_PREFIXES) {
    if (t.startsWith(p)) return true;
  }
  return t.startsWith('"""') || t.startsWith("'''");
}

export const stubsDetector: Detector = {
  id: "stubs",
  name: "Stub / Placeholder Code",
  run(ctx: DetectorContext) {
    const start = Date.now();
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      for (const { lineNumber, text } of file.addedLines) {
        const isComment = isCommentLine(text);
        for (const rule of RULES) {
          const patterns = rule.patterns[file.language] ?? rule.patterns[ALL];
          if (!patterns) continue;
          for (const re of patterns) {
            if (!re.test(text)) continue;

            if (isComment && rule.id !== "todo") continue;
            findings.push(buildFinding(rule, file.path, lineNumber, text.trim().slice(0, 120)));
          }
        }
      }
    }

    return { detector: "stubs", findings, durationMs: Date.now() - start };
  },
};

function buildFinding(rule: StubRule, file: string, line: number, snippet: string): Finding {
  return {
    id: `stub:${rule.id}`,
    category: "stub",
    severity: rule.severity,
    detector: "stubs",
    title: rule.title,
    message: rule.message,
    location: { file, startLine: line, endLine: line },
    snippet,
  };
}

export { RULES as STUB_RULES };

export type { DiffLine };

import type { Finding, ScanReport, SeverityLevel } from "../types.js";

const SEVERITY_TO_LEVEL: Record<SeverityLevel, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function renderSarif(report: ScanReport): string {
  const rules = buildRules(report.findings);
  const results = report.findings.map((f) => toResult(f, rules));

  const sarif = {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "haluguard",
            informationUri: "https://github.com/yadavnikhil03/haluguard",
            version: "0.1.0",
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

interface RuleIndex {
  key: string;
  index: number;
  rule: object;
}

function buildRules(findings: Finding[]): RuleIndex[] {
  const seen = new Map<string, RuleIndex>();
  let i = 0;
  for (const f of findings) {
    const key = `${f.detector}/${f.id}`;
    if (seen.has(key)) continue;
    seen.set(key, {
      key,
      index: i++,
      rule: {
        id: f.id,
        name: f.detector,
        shortDescription: { text: f.title },
        fullDescription: { text: f.message.slice(0, 500) },
        defaultConfiguration: { level: SEVERITY_TO_LEVEL[f.severity] },
        properties: { category: f.category, precision: "high" },
      },
    });
  }
  return [...seen.values()];
}

function toResult(f: Finding, rules: RuleIndex[]): object {
  const ruleKey = `${f.detector}/${f.id}`;
  const rule = rules.find((r) => r.key === ruleKey);
  return {
    ruleId: f.id,
    ruleIndex: rule?.index ?? 0,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.location.file },
          region: {
            startLine: f.location.startLine,
            endLine: f.location.endLine,
            ...(f.location.startColumn ? { startColumn: f.location.startColumn } : {}),
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: hash(`${f.location.file}:${f.location.startLine}:${f.snippet}`),
    },
  };
}

function hash(input: string): string {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) + h + input.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(16);
}

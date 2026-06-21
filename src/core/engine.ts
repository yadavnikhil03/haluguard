import { hallucinatedApiDetector } from "../detectors/hallucinated-apis.js";
import { type Detector, listDetectors, registerDetector } from "../detectors/registry.js";
import { secretsDetector } from "../detectors/secrets.js";
import { stubsDetector } from "../detectors/stubs.js";
import type {
  DetectorResult,
  FileChange,
  Finding,
  ScanOptions,
  ScanReport,
  SeverityLevel,
} from "../types.js";
import { Severity } from "../types.js";

const DEFAULT_OPTIONS: ScanOptions = {
  cwd: process.cwd(),
  minSeverity: "info",
  ignore: [],
};

let builtinsRegistered = false;

export function registerBuiltinDetectors(): void {
  if (builtinsRegistered) return;
  registerDetector({ create: () => secretsDetector });
  registerDetector({ create: () => hallucinatedApiDetector });
  registerDetector({ create: () => stubsDetector });
  builtinsRegistered = true;
}

export async function runScan(
  files: FileChange[],
  userOptions: Partial<ScanOptions> = {},
): Promise<ScanReport> {
  registerBuiltinDetectors();

  const options: ScanOptions = { ...DEFAULT_OPTIONS, ...userOptions };
  const start = Date.now();

  const all = listDetectors();
  const selected = options.detectors ? all.filter((d) => options.detectors?.includes(d.id)) : all;

  const results = await Promise.all(selected.map((d) => runOne(d, files, options)));

  const findings = applyFilters(results, options);
  const linesScanned = files.reduce((n, f) => n + f.addedLines.length, 0);

  return {
    findings,
    stats: {
      filesScanned: files.length,
      linesScanned,
      detectorStats: results.map((r) => ({
        detector: r.detector,
        findings: r.findings.length,
        durationMs: r.durationMs,
      })),
      totalMs: Date.now() - start,
    },
  };
}

async function runOne(
  detector: Detector,
  files: FileChange[],
  options: ScanOptions,
): Promise<DetectorResult> {
  try {
    const result = await detector.run({ files, options });

    return {
      detector: detector.id,
      findings: result.findings,
      durationMs: result.durationMs || 0,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`haluguard: detector "${detector.id}" crashed: ${msg}\n`);
    return { detector: detector.id, findings: [], durationMs: 0 };
  }
}

function applyFilters(results: DetectorResult[], options: ScanOptions): Finding[] {
  const minSeverity = Severity[options.minSeverity ?? "info"];
  const ignoreMatchers = (options.ignore ?? []).map((g) => globToRegExp(g));

  const merged: Finding[] = [];
  for (const r of results) {
    for (const f of r.findings) {
      if (Severity[f.severity] < minSeverity) continue;
      if (ignoreMatchers.some((re) => re.test(f.location.file))) continue;
      merged.push(f);
    }
  }

  merged.sort(bySeverityThenLocation);
  return dedupe(merged);
}

function bySeverityThenLocation(a: Finding, b: Finding): number {
  const sev = Severity[b.severity] - Severity[a.severity];
  if (sev !== 0) return sev;
  if (a.location.file !== b.location.file) {
    return a.location.file.localeCompare(b.location.file);
  }
  return a.location.startLine - b.location.startLine;
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.detector}|${f.location.file}|${f.location.startLine}|${f.snippet}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if ("\\^$.+()|{}[]".includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

export type { SeverityLevel };

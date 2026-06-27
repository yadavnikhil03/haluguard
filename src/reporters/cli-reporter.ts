import picocolors from "picocolors";
import type { Finding, ScanReport, SeverityLevel } from "../types.js";

const SEVERITY_STYLE: Record<
  SeverityLevel,
  { label: string; tag: (s: string) => string; icon: string }
> = {
  critical: { label: "CRIT", tag: (s) => picocolors.bgRed(picocolors.white(s)), icon: "[X]" },
  high: { label: "HIGH", tag: (s) => picocolors.red(s), icon: "[!]" },
  medium: { label: "MED ", tag: (s) => picocolors.yellow(s), icon: "[-]" },
  low: { label: "LOW ", tag: (s) => picocolors.blue(s), icon: "[*]" },
  info: { label: "INFO", tag: (s) => picocolors.gray(s), icon: "[i]" },
};

export function renderReport(report: ScanReport): string {
  if (report.findings.length === 0) {
    return successBanner(report);
  }

  const lines: string[] = [];
  lines.push(
    picocolors.bold(
      picocolors.red(
        `\n  [!] HaluGuard found ${report.findings.length} issue${report.findings.length === 1 ? "" : "s"}\n`,
      ),
    ),
  );

  const byFile = groupByFile(report.findings);
  for (const [file, findings] of byFile) {
    lines.push(picocolors.underline(picocolors.cyan(`  ${file}`)));
    for (const f of findings) {
      lines.push(renderFinding(f));
    }
    lines.push("");
  }

  lines.push(renderSummary(report));
  return lines.join("\n");
}

function renderFinding(f: Finding): string {
  const style = SEVERITY_STYLE[f.severity];
  const loc = picocolors.gray(`${f.location.startLine}`);
  const sev = style.tag(style.label);
  const title = picocolors.bold(f.title);
  const header = `    ${style.icon} ${sev} ${loc}  ${title}`;
  const body = picocolors.gray(wrap(`       ${f.message}`, 100));
  const snippet = picocolors.gray(`       → ${f.snippet}`);
  const detector = picocolors.dim(`       [${f.detector}]`);
  return `${header}\n${body}\n${snippet}\n${detector}`;
}

function renderSummary(report: ScanReport): string {
  const s = report.stats;
  const counts = countBySeverity(report.findings);
  const chips = Object.entries(counts)
    .map(([sev, n]) => SEVERITY_STYLE[sev as SeverityLevel].tag(`${n} ${sev}`))
    .join("  ");

  const detectorLines = s.detectorStats
    .map((d) => {
      const findings =
        d.findings === 0 ? picocolors.gray("0") : picocolors.yellow(String(d.findings));
      return `     ${d.detector.padEnd(22)} ${findings.padEnd(6)} ${picocolors.gray(`${d.durationMs}ms`)}`;
    })
    .join("\n");

  return [
    picocolors.dim("  ────────────────────────────────────────────"),
    `  ${chips}`,
    "",
    picocolors.dim(
      `  Scanned ${s.filesScanned} files, ${s.linesScanned} added lines in ${s.totalMs}ms`,
    ),
    detectorLines,
    "",
  ].join("\n");
}

function successBanner(report: ScanReport): string {
  const s = report.stats;
  return [
    "",
    picocolors.bold(picocolors.green("  [✓] No AI code issues found.")),
    picocolors.dim(
      `     Scanned ${s.filesScanned} files, ${s.linesScanned} added lines in ${s.totalMs}ms.`,
    ),
    "",
  ].join("\n");
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = map.get(f.location.file) ?? [];
    arr.push(f);
    map.set(f.location.file, arr);
  }
  return map;
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const order: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];
  const ordered: Record<string, number> = {};
  for (const sev of order) {
    if (counts[sev]) ordered[sev] = counts[sev];
  }
  return ordered;
}

function wrap(text: string, width: number): string {
  if (text.length <= width) return text;
  const words = text.split(" ");
  const out: string[] = [];
  let line = "";
  const indent = "       ";
  for (const w of words) {
    if (`${line} ${w}`.trim().length > width) {
      out.push(line.trim());
      line = w;
    } else {
      line = `${line} ${w}`.trim();
    }
  }
  if (line) out.push(line.trim());
  return out.join(`\n${indent}`);
}

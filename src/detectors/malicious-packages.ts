import type { DiffLine, Finding } from "../types.js";
import type { Detector, DetectorContext } from "./registry.js";

interface MaliciousSignature {
  id: string;
  title: string;
  match: (text: string) => boolean;
}

const TYPOSQUAT_SIGNATURES: MaliciousSignature[] = [
  {
    id: "typosquat_npm",
    title: "Typosquatted npm package (require)",
    match: (text) => {
      const m = /\brequire\(["']([^"']+)["']\)/.exec(text);
      if (!m) return false;
      return isSuspicious(m[1]);
    },
  },
  {
    id: "typosquat_import",
    title: "Typosquatted npm package (import)",
    match: (text) => {
      const m = /(?:from|import)\s+["']([^"']+)["']/.exec(text);
      if (!m) return false;
      return isSuspicious(m[1]);
    },
  },
  {
    id: "typosquat_python",
    title: "Typosquatted PyPI package",
    match: (text) => {
      const m = /^\s*(?:import|from)\s+([\w.]+)/.exec(text);
      if (!m) return false;
      return isSuspicious(m[1].split(".")[0]);
    },
  },
];

const KNOWN_TYPOSQUATS = new Set([
  "babel-sintax",
  "debugl",
  "expressjs",
  "http-proxy-middlware",
  "loadash",
  "mongose",
  "nodemailor",
  "nodmeailer",
  "react-dome",
  "socketio",
]);

function isSuspicious(name: string): boolean {
  const base = name.startsWith("@")
    ? name.slice(0, name.indexOf("/", 1) + 1)
    : name.includes("/")
      ? name.slice(0, name.indexOf("/"))
      : name;
  return KNOWN_TYPOSQUATS.has(base);
}

function detectInFile(path: string, addedLines: DiffLine[]): Finding[] {
  const findings: Finding[] = [];
  for (const { lineNumber, text } of addedLines) {
    for (const sig of TYPOSQUAT_SIGNATURES) {
      if (sig.match(text)) {
        findings.push({
          id: `malicious:${sig.id}`,
          category: "malicious_package",
          severity: "high",
          detector: "malicious_packages",
          title: sig.title,
          message:
            "This line references a package that matches a known typosquatting pattern. Typosquatted packages are often used in supply-chain attacks to distribute malware. Verify the package name carefully against the official package registry before installing.",
          location: { file: path, startLine: lineNumber, endLine: lineNumber },
          snippet: text.trim().slice(0, 120),
        });
        break;
      }
    }
  }
  return findings;
}

export const maliciousPackageDetector: Detector = {
  id: "malicious_packages",
  name: "Malicious / Typosquatted Packages",
  run(ctx: DetectorContext) {
    const start = Date.now();
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      findings.push(...detectInFile(file.path, file.addedLines));
    }
    return { detector: "malicious_packages", findings, durationMs: Date.now() - start };
  },
};

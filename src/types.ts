export const Severity = {
  info: 10,
  low: 20,
  medium: 30,
  high: 40,
  critical: 50,
} as const;

export type SeverityLevel = keyof typeof Severity;

export type FindingCategory =
  | "hallucinated_api"
  | "malicious_package"
  | "secret"
  | "stub"
  | "ai_logic";

export interface Location {
  file: string;
  startLine: number;
  endLine: number;

  startColumn?: number;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: SeverityLevel;

  detector: string;

  title: string;

  message: string;
  location: Location;

  snippet: string;

  confidence?: number;
}

export type FileLanguage =
  | "typescript"
  | "javascript"
  | "tsx"
  | "jsx"
  | "python"
  | "go"
  | "rust"
  | "java"
  | "ruby"
  | "php"
  | "csharp"
  | "unknown";

export interface FileChange {
  path: string;
  language: FileLanguage;

  addedLines: DiffLine[];

  newContent?: string;

  rawLines?: Map<number, string>;
}

export interface DiffLine {
  lineNumber: number;
  text: string;
}

export interface DetectorResult {
  detector: string;
  findings: Finding[];

  durationMs: number;
}

export interface ScanOptions {
  cwd: string;

  detectors?: string[];

  minSeverity?: SeverityLevel;

  ignore?: string[];
}

export interface ScanReport {
  findings: Finding[];
  stats: {
    filesScanned: number;
    linesScanned: number;
    detectorStats: Array<{ detector: string; findings: number; durationMs: number }>;
    totalMs: number;
  };
}

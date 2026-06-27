import * as path from "node:path";
import * as vscode from "vscode";

interface HaluGuardEngine {
  parseFileContent: (path: string, content: string) => unknown;
  runScan: (files: unknown[], options: Record<string, unknown>) => Promise<ScanReport>;
}

interface ScanReport {
  findings: Finding[];
}

interface Finding {
  id: string;
  severity: string;
  message: string;
  snippet?: string;
  location: { file: string; startLine: number; endLine: number };
}

let haluguardModule: HaluGuardEngine | null = null;
let diagnosticCollection: vscode.DiagnosticCollection;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

async function loadEngine(): Promise<HaluGuardEngine> {
  if (haluguardModule) return haluguardModule;
  const enginePath = path.resolve(__dirname, "../../dist/index.js");
  haluguardModule = (await import(enginePath)) as HaluGuardEngine;
  return haluguardModule;
}

async function analyzeDocument(document: vscode.TextDocument): Promise<void> {
  const config = vscode.workspace.getConfiguration("haluguard");
  if (!config.get<boolean>("enabled", true)) return;

  const supportedLanguages = [
    "typescript",
    "javascript",
    "typescriptreact",
    "javascriptreact",
    "python",
    "rust",
    "java",
    "php",
    "csharp",
  ];

  if (!supportedLanguages.includes(document.languageId)) return;

  let engine: HaluGuardEngine;
  try {
    engine = await loadEngine();
  } catch {
    return;
  }

  const filePath = document.uri.fsPath;
  const content = document.getText();

  const fileChange = engine.parseFileContent(filePath, content);
  const report = await engine.runScan([fileChange], {
    cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || path.dirname(filePath),
    minSeverity: config.get<string>("minSeverity", "info"),
  });

  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of report.findings) {
    const line = Math.max(0, finding.location.startLine - 1);
    const endLine = Math.max(0, finding.location.endLine - 1);
    const docLine = document.lineAt(Math.min(line, document.lineCount - 1));

    let startCol = 0;
    let endCol = docLine.text.length;

    if (finding.snippet) {
      const snippetClean = finding.snippet.trim();
      const idx = docLine.text.indexOf(snippetClean);
      if (idx >= 0) {
        startCol = idx;
        endCol = idx + snippetClean.length;
      }
    }

    const range = new vscode.Range(
      new vscode.Position(line, startCol),
      new vscode.Position(endLine, endCol),
    );

    const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;
    const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
    diagnostic.source = "HaluGuard";
    diagnostic.code = finding.id;
    diagnostics.push(diagnostic);
  }

  diagnosticCollection.set(document.uri, diagnostics);
}

function scheduleAnalysis(document: vscode.TextDocument): void {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => analyzeDocument(document), 500);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("haluguard");
  context.subscriptions.push(diagnosticCollection);

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration("haluguard");
      if (config.get<boolean>("runOnSave", true)) {
        analyzeDocument(document);
      }
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration("haluguard");
      if (config.get<boolean>("runOnType", false)) {
        scheduleAnalysis(event.document);
      }
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      analyzeDocument(document);
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnosticCollection.delete(document.uri);
    }),
  );

  for (const document of vscode.workspace.textDocuments) {
    analyzeDocument(document);
  }
}

export function deactivate(): void {
  if (debounceTimer) clearTimeout(debounceTimer);
  diagnosticCollection?.dispose();
}

"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
let haluguardModule = null;
let diagnosticCollection;
let debounceTimer;
const SEVERITY_MAP = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
    info: vscode.DiagnosticSeverity.Hint,
};
async function loadEngine() {
    if (haluguardModule)
        return haluguardModule;
    const enginePath = path.resolve(__dirname, "../../dist/index.js");
    haluguardModule = await Promise.resolve(`${enginePath}`).then(s => __importStar(require(s)));
    return haluguardModule;
}
async function analyzeDocument(document) {
    const config = vscode.workspace.getConfiguration("haluguard");
    if (!config.get("enabled", true))
        return;
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
    if (!supportedLanguages.includes(document.languageId))
        return;
    let engine;
    try {
        engine = await loadEngine();
    }
    catch {
        return;
    }
    const filePath = document.uri.fsPath;
    const content = document.getText();
    const fileChange = engine.parseFileContent(filePath, content);
    const report = await engine.runScan([fileChange], {
        cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || path.dirname(filePath),
        minSeverity: config.get("minSeverity", "info"),
    });
    const diagnostics = [];
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
        const range = new vscode.Range(new vscode.Position(line, startCol), new vscode.Position(endLine, endCol));
        const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;
        const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
        diagnostic.source = "HaluGuard";
        diagnostic.code = finding.id;
        diagnostics.push(diagnostic);
    }
    diagnosticCollection.set(document.uri, diagnostics);
}
function scheduleAnalysis(document) {
    if (debounceTimer)
        clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => analyzeDocument(document), 500);
}
function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection("haluguard");
    context.subscriptions.push(diagnosticCollection);
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((document) => {
        const config = vscode.workspace.getConfiguration("haluguard");
        if (config.get("runOnSave", true)) {
            analyzeDocument(document);
        }
    }));
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        const config = vscode.workspace.getConfiguration("haluguard");
        if (config.get("runOnType", false)) {
            scheduleAnalysis(event.document);
        }
    }));
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((document) => {
        analyzeDocument(document);
    }));
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((document) => {
        diagnosticCollection.delete(document.uri);
    }));
    vscode.workspace.textDocuments.forEach((document) => {
        analyzeDocument(document);
    });
}
function deactivate() {
    if (debounceTimer)
        clearTimeout(debounceTimer);
    diagnosticCollection?.dispose();
}
//# sourceMappingURL=extension.js.map
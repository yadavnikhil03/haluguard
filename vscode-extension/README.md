# HaluGuard for VS Code

Real-time detection of hallucinated APIs, leaked secrets, and stubs in AI-generated code.

## What it does

HaluGuard analyzes your code as you work and highlights problems directly in the editor:

| Finding | Shown as |
|---------|----------|
| Hallucinated API (e.g. `fs.readFileContent()`) | ⚠️ Yellow warning underline |
| Leaked secret (API key, token) | 🔴 Red error underline |
| Stub / placeholder code (`TODO: implement`) | 💡 Blue info underline |

All analysis runs locally. No data leaves your machine.

## Setup

From the repository root:

```sh
npm run build
cd vscode-extension
npm install
npm run compile
```

Then press **F5** in VS Code to launch the Extension Development Host.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `haluguard.enabled` | `true` | Enable/disable analysis |
| `haluguard.runOnSave` | `true` | Analyze on file save |
| `haluguard.runOnType` | `false` | Analyze as you type (slower) |
| `haluguard.minSeverity` | `info` | Minimum severity to show |

## Supported Languages

TypeScript, JavaScript, Python, Rust, Java, PHP, C#

#!/bin/sh
# HaluGuard pre-commit hook — scans staged changes for AI hallucinations
DIFF=$(git diff --cached --unified=0)
if [ -z "$DIFF" ]; then exit 0; fi
echo "$DIFF" | npx haluguard --stdin --fail-on high

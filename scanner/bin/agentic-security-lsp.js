#!/usr/bin/env node
// agentic-security LSP server — stdio entry point.
//
// Speaks the Language Server Protocol (vscode-jsonrpc framing) on stdin/stdout.
// Used by the JetBrains plugin (via LSP4IJ) and the Neovim plugin (via
// built-in LSP). Diagnostics emitted to publishDiagnostics on save/open.
//
// Usage (typically invoked by an editor, not directly):
//   node bin/agentic-security-lsp.js
//
import { startLspServer } from '../src/lsp/server.js';
startLspServer();

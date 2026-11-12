'use strict';

const path = require('node:path');
const fs = require('node:fs');
const Module = require('node:module');

class Position {
  constructor(line, character) {
    this.line = line;
    this.character = character;
  }
}

class Range {
  constructor(startLineOrPos, startCharOrEndPos, endLine, endChar) {
    if (typeof startLineOrPos === 'number') {
      this.start = new Position(startLineOrPos, startCharOrEndPos);
      this.end = new Position(endLine ?? startLineOrPos, endChar ?? startCharOrEndPos);
    } else {
      this.start = startLineOrPos;
      this.end = startCharOrEndPos;
    }
  }
}

class Diagnostic {
  constructor(range, message, severity) {
    this.range = range;
    this.message = message;
    this.severity = severity;
    this.source = undefined;
    this.code = undefined;
  }
}

const DiagnosticSeverity = {
  Error: 0,
  Warning: 1,
  Information: 2,
  Hint: 3
};

class Uri {
  constructor(fsPath) {
    this.fsPath = path.resolve(fsPath);
    this.scheme = 'file';
  }
  static file(filePath) {
    return new Uri(filePath);
  }
  static joinPath(baseUri, ...segments) {
    return new Uri(path.resolve(baseUri.fsPath, ...segments));
  }
  toString() {
    return `file://${this.fsPath}`;
  }
}

class DiagnosticCollection {
  constructor(name) {
    this.name = name;
    this.map = new Map();
  }
  clear() {
    this.map.clear();
  }
  set(uri, diagnostics) {
    this.map.set(uri.toString(), diagnostics);
  }
  get(uri) {
    return this.map.get(uri.toString());
  }
  delete(uri) {
    this.map.delete(uri.toString());
  }
  dispose() {
    this.clear();
  }
}

function createTextDocument(filePath, content) {
  const lines = content.split(/\r?\n/);
  return {
    uri: Uri.file(filePath),
    fileName: filePath,
    lineCount: lines.length,
    lineAt(index) {
      const text = lines[index] ?? '';
      return {
        text,
        lineNumber: index,
        range: new Range(index, 0, index, text.length)
      };
    },
    getText() {
      return content;
    }
  };
}

let mockConfig = {};

const vscodeMock = {
  Position,
  Range,
  Diagnostic,
  DiagnosticSeverity,
  Uri,
  DiagnosticCollection,
  StatusBarAlignment: { Left: 1, Right: 2 },
  ProgressLocation: { SourceControl: 1, Window: 10, Notification: 15 },
  ViewColumn: { Active: -1, Beside: -2, One: 1, Two: 2, Three: 3 },
  workspace: {
    getConfiguration(section) {
      return {
        get(key, defaultValue) {
          const fullKey = section ? `${section}.${key}` : key;
          if (mockConfig[fullKey] !== undefined) return mockConfig[fullKey];
          if (mockConfig[key] !== undefined) return mockConfig[key];
          return defaultValue;
        }
      };
    },
    async openTextDocument(uriOrPath) {
      const filePath = typeof uriOrPath === 'string' ? uriOrPath : uriOrPath.fsPath;
      const content = await fs.promises.readFile(filePath, 'utf8');
      return createTextDocument(filePath, content);
    },
    workspaceFolders: [
      { uri: Uri.file(path.resolve(__dirname, '..', '..')), name: 'shieldops' }
    ],
    fs: {
      async readFile(uri) {
        return fs.promises.readFile(uri.fsPath);
      },
      async writeFile(uri, content) {
        return fs.promises.writeFile(uri.fsPath, content);
      }
    }
  },
  window: {
    createOutputChannel(name) {
      const logs = [];
      return {
        name,
        logs,
        append(s) { logs.push(s); },
        appendLine(s) { logs.push(s + '\n'); },
        show() {},
        dispose() {}
      };
    },
    createStatusBarItem() {
      return {
        text: '',
        tooltip: '',
        command: '',
        show() {},
        hide() {},
        dispose() {}
      };
    },
    createWebviewPanel(viewType, title, column, options) {
      return {
        viewType,
        title,
        column,
        options,
        webview: {
          html: '',
          onDidReceiveMessage() {},
          postMessage() {}
        },
        reveal() {},
        onDidDispose() {},
        dispose() {}
      };
    },
    showInformationMessage: async () => undefined,
    showWarningMessage: async () => undefined,
    showErrorMessage: async () => undefined,
    showSaveDialog: async () => undefined,
    withProgress: async (options, task) => {
      const progress = { report() {} };
      const token = { isCancellationRequested: false, onCancellationRequested() {} };
      return task(progress, token);
    }
  },
  commands: {
    registered: new Map(),
    registerCommand(id, handler) {
      this.registered.set(id, handler);
      return { dispose: () => this.registered.delete(id) };
    },
    async executeCommand(id, ...args) {
      const handler = this.registered.get(id);
      if (handler) return handler(...args);
      return undefined;
    }
  },
  languages: {
    createDiagnosticCollection(name) {
      return new DiagnosticCollection(name);
    }
  },
  _setMockConfig(newConfig) {
    mockConfig = { ...newConfig };
  },
  _resetMockConfig() {
    mockConfig = {};
  }
};

// Hook into Node module resolution so require('vscode') resolves to vscodeMock
const fakeVscodePath = path.resolve(__dirname, '__fake_vscode__');
require.cache[fakeVscodePath] = {
  id: fakeVscodePath,
  filename: fakeVscodePath,
  loaded: true,
  exports: vscodeMock
};

const origResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
  if (request === 'vscode') {
    return fakeVscodePath;
  }
  return origResolve.call(this, request, parent, isMain, options);
};

module.exports = vscodeMock;

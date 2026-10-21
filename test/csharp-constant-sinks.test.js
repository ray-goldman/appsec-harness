'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isConstantCSharpSink } = require('../src/csharp-constant-sinks');
const { scan } = require('../src/engine');

test('proves command arguments constant when all local assignments are literals', () => {
  const code = `class Sample {
    void Run() {
      string data;
      if (flag) { data = "foo"; } else { data = null; }
      string command = "cmd /c ";
      Process.Start(command + data);
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 5, ruleId: 'CS-CMDI-001' }), true);
});

test('unrelated loop counter updates do not invalidate constant sink arguments', () => {
  const code = `class Sample {
    void Run() {
      string data = "fixed";
      for (int i = 0; i < 1; i++) {
        string command = "/bin/ls ";
        Process.Start(command + data);
      }
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 5, ruleId: 'CS-CMDI-001' }), true);
});

test('does not prove a command argument constant when a local receives a method result', () => {
  const code = `class Sample {
    void Run() {
      string data = ReadLine();
      Process.Start("cmd /c " + data);
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 3, ruleId: 'CS-CMDI-001' }), false);
});

test('does not suppress Process.Start when the executable is constant but a later argument is dynamic', () => {
  const code = `class Sample {
    void Run(string args) {
      string suffix = "";
      Process.Start("cmd.exe", args + suffix);
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 3, ruleId: 'CS-CMDI-001' }), false);
});

test('does not prove a SQL expression constant when a referenced value has an unknown write', () => {
  const code = `class Sample {
    void Run(string input) {
      string name = "fixed";
      if (flag) { name = input; }
      command.CommandText = "select * from users where name='" + name + "'";
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 4, ruleId: 'CS-SQLI-001' }), false);
});

test('proves direct SQL string concatenation constant without suppressing unrelated sink forms', () => {
  const code = `class Sample {
    void Run() {
      string name = "fixed";
      command.CommandText = "select * from users where name='" + name + "'";
    }
  }`;
  assert.equal(isConstantCSharpSink({ code, line: 3, ruleId: 'CS-SQLI-001' }), true);
  assert.equal(isConstantCSharpSink({ code, line: 3, ruleId: 'CS-CMDI-001' }), false);
});

test('scanner suppresses only the proven literal C# SQL and command constructions', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-csharp-constant-sinks-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'Safe.cs'), `class Safe {
    void Sql() {
      string name = "fixed";
      command.CommandText = "select '" + name + "'";
    }
    void Command() {
      string arg = "status";
      string command = "cmd /c ";
      Process.Start(command + arg);
    }
  }`);
  fs.writeFileSync(path.join(root, 'Unsafe.cs'), `class Unsafe {
    void Sql(string name) {
      command.CommandText = "select '" + name + "'";
    }
    void Command(string arg) {
      string command = "cmd /c ";
      Process.Start(command + arg);
    }
    void CommandArguments(string arg) {
      Process.Start("cmd.exe", arg + " /c");
    }
  }`);
  const result = await scan(root, { includeTests: true });
  assert.deepEqual(result.findings.filter(finding => ['CS-SQLI-001', 'CS-CMDI-001'].includes(finding.ruleId))
    .map(finding => [finding.ruleId, finding.file]).sort(), [
    ['CS-CMDI-001', 'Unsafe.cs'], ['CS-CMDI-001', 'Unsafe.cs'], ['CS-SQLI-001', 'Unsafe.cs'],
  ]);
});

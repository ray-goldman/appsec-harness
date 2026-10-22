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

function constantProof(body, members = '', ruleId = 'CS-CMDI-001') {
  const code = `class Sample {\n${members}\n${body}\n}`;
  const line = code.split('\n').findIndex(text => text.includes('Process.Start(') || text.includes('command.CommandText ='));
  return isConstantCSharpSink({ code, line, ruleId });
}

test('constant proofs follow uniquely resolved private helper returns on every branch', () => {
  assert.equal(constantProof('void Run() {\n Process.Start("cmd /c " + Value());\n}',
    'private string Value() { string value; if (flag) { value = "status"; } else { value = null; } return value; }'), true);
  assert.equal(constantProof('void Run() {\n Process.Start("cmd /c " + Value());\n}',
    'private string Value() { if (flag) { return Request.Query["cmd"]; } return "status"; }'), false);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("cmd /c " + Value(input));\n}',
    'private string Value(string unused) { return "status"; }'), true);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("cmd /c " + Value(input));\n}',
    'private string Value(string value) { return value; }'), false);
});

test('constant proofs distinguish locals with the same name in disjoint scopes', () => {
  assert.equal(constantProof('void Run() { string copy; { string value = "fixed"; copy = value; } { string value = copy;\n Process.Start("cmd /c " + value);\n} }'), true);
  assert.equal(constantProof('void Run(string input) { string copy; { string value = input; copy = value; } { string value = copy;\n Process.Start("cmd /c " + value);\n} }'), false);
});

test('private helper parameters require all visible callers to supply proven constants', () => {
  const sink = 'private static void Sink(string value) {\n Process.Start("cmd /c " + value);\n}';
  assert.equal(constantProof(sink, 'void Run() { string value = "fixed"; Sink(value); }'), true);
  assert.equal(constantProof(sink, 'void Run(string input) { Sink("fixed"); Sink(input); }'), false);
  assert.equal(constantProof(sink.replace('private', 'public'), 'void Run() { Sink("fixed"); }'), false);
  assert.equal(constantProof(sink, 'void Run() { Sink("fixed"); var callback = Sink; }'), false);
  assert.equal(constantProof(sink.replace('Process.Start(', 'value = Request.Query["cmd"]; Process.Start('), 'void Run() { Sink("fixed"); }'), false);
});

test('private fields are safe only if every write and alias is proved constant', () => {
  const sink = 'void Run() { string value = saved;\n Process.Start("cmd /c " + value);\n}';
  assert.equal(constantProof(sink, 'private string saved; void Set() { string value = "fixed"; saved = value; }'), true);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) { saved = input; }'), false);
  assert.equal(constantProof(sink, 'public string saved; void Set() { saved = "fixed"; }'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set() { saved = "fixed"; Mutate(ref saved); }'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) => saved = input;'), false);
  assert.equal(constantProof(sink, 'private string saved; string Setter { set { saved = value; } }'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) { var text = $"{saved = input}"; }'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) { string other = ""; (saved, other) = (input, ""); }'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) { saved ??= input; }'), false);
  assert.equal(constantProof('void Run(object input) { if (input is string saved) {\n Process.Start("cmd /c " + saved);\n} }', 'private string saved;'), false);
  assert.equal(constantProof('void Run(string input) { if (input is { } saved) {\n Process.Start("cmd /c " + saved);\n} }', 'private string saved;'), false);
  assert.equal(constantProof('void Run() { try { Work(); } catch (System.Exception saved) {\n Process.Start("cmd /c " + saved);\n} }', 'private string saved;'), false);
  assert.equal(constantProof('void Run() { try { Work(); } catch (CustomException<string> saved) {\n Process.Start("cmd /c " + saved);\n} }', 'private string saved;'), false);
  assert.equal(constantProof(sink, 'private String saved;'), false);
  assert.equal(constantProof(sink, 'private string saved; void Set(string input) { try { Work(); } catch(CustomException<string> saved) { } saved = input; }'), false);
});

test('helper proofs reject recursion, ambiguous overloads, virtual dispatch and mutation', () => {
  const body = 'void Run() {\n Process.Start("cmd /c " + Value());\n}';
  for (const members of [
    'private string Value() { return Value(); }',
    'private string Value() { return "fixed"; } private string Value(int n = 0) { return Request.Query["cmd"]; }',
    'protected virtual string Value() { return "fixed"; }',
    'private string Value() { string value = "fixed"; Mutate(ref value); return value; }',
    'private string Value() { return "fixed"; } void Other() { var Value = ReadDelegate(); Value(); }',
  ]) assert.equal(constantProof(body, members), false, members);
  assert.equal(constantProof('void Run(System.Func<string> Value) {\n Process.Start("cmd /c " + Value());\n}', 'private string Value() { return "fixed"; }'), false);
  assert.equal(constantProof('void Run() { System.Func<string> Value = ReadDelegate();\n Process.Start("cmd /c " + Value());\n}', 'private string Value() { return "fixed"; }'), false);
  assert.equal(constantProof('void Run(dynamic Sample) {\n Process.Start("cmd /c " + Sample.Value());\n}', 'private string Value() { return "fixed"; }'), false);
  assert.equal(constantProof(body, 'private AttackerText Value() { return "fixed"; }'), false);
  assert.equal(constantProof('private void Sink(String value) {\n Process.Start("cmd /c " + value);\n}', 'void Run() { Sink("fixed"); }'), false);
});

test('sanitizer names and encoding for the wrong sink category never prove safety', () => {
  assert.equal(constantProof('void Run(string input) {\n Process.Start("cmd /c " + EscapeArgument(input));\n}',
    'private string EscapeArgument(string input) { return input; }'), false);
  assert.equal(constantProof('void Run(string input) {\n command.CommandText = "select " + HtmlEncode(input);\n}',
    'private string HtmlEncode(string input) { return input; }', 'CS-SQLI-001'), false);
});

test('direct local proofs reject deconstruction writes and aliased scalar conversions', () => {
  assert.equal(constantProof('void Run(string input) { string value = "fixed"; string other = ""; (value, other) = (input, "");\n Process.Start("cmd /c " + value);\n}'),false);
  const code='using String = External.AttackerText;\nclass Sample { private string Value() { String text = "fixed"; return text; }\nvoid Run() {\n Process.Start("cmd /c " + Value());\n} }';
  assert.equal(isConstantCSharpSink({code,line:3,ruleId:'CS-CMDI-001'}),false);
});

test('command proofs check every executable and argument expression on a line', () => {
  assert.equal(constantProof('void Run() { string arg = "status";\n Process.Start("cmd.exe", "/c " + arg);\n}'), true);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("cmd.exe", "/c " + input);\n}'), false);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("fixed"); Process.Start("cmd /c " + input);\n}'), false);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("fixed"); info.Arguments = "/c " + input;\n}'), false);
  assert.equal(constantProof('void Run(string input) {\n Process.Start("cmd.exe", "/c " + input); Process.Start("fixed");\n}'), false);
  assert.equal(constantProof('void Run() {\n Process.Start("tool", "--version"); Process.Start("other", "--help");\n}'), true);
  assert.equal(constantProof('void Run() { String arg = "status";\n Process.Start("cmd.exe", "/c " + arg);\n}'),false);
  assert.equal(constantProof('void Run() { var arg = "status";\n Process.Start("cmd.exe", "/c " + arg);\n}'),false);
});

test('command proofs accept constant-only conditional and null-coalescing values', () => {
  assert.equal(constantProof('void Run(bool flag) { string data = flag ? "status" : "help";\n Process.Start("cmd /c " + data);\n}'), true);
  assert.equal(constantProof('void Run(bool flag, bool other) { string data = flag ? (other ? "status" : "help") : null;\n Process.Start("cmd /c " + (data ?? "version"));\n}'), true);
  assert.equal(constantProof('void Run(string input, bool flag) { string data = flag ? "status" : input;\n Process.Start("cmd /c " + data);\n}'), false);
  assert.equal(constantProof('void Run(string input) { string data = input ?? "status";\n Process.Start("cmd /c " + data);\n}'), false);
  assert.equal(constantProof('void Run(string input, bool flag) { string data = "status"; bool other = flag && ((data = input) != null);\n Process.Start("cmd /c " + (other ? data : "help"));\n}'), false);
});

test('conditional proofs never confuse reordered named helper arguments with conditions', () => {
  const members='private string Value(string command, string unused) { return command; }';
  assert.equal(constantProof('void Run(string input, bool flag) { string shell = "cmd /c ";\n Process.Start(shell + Value(unused: flag ? "fixed" : "fixed", command: input));\n}',members),false);
  assert.equal(constantProof('void Run(string input, bool flag) { string shell = "cmd /c ";\n Process.Start(shell + Value(unused: flag ? "fixed" : "fixed", command: input ?? "fixed"));\n}',members),false);
});

test('explicit built-in string aliases support closed private helper proofs', () => {
  const code = `using String = string;
class Sample {
 private String Value() { String text = "status"; return text; }
 void Run() {
  Process.Start("cmd /c " + Value());
 }
}`;
  assert.equal(isConstantCSharpSink({code,line:4,ruleId:'CS-CMDI-001'}),true);
  for(const unsafe of [
    code.replace('using String = string;', 'using String = External.Text;'),
    code.replace('using String = string;', 'using System;'),
    code.replace('class Sample {','class Sample : ExternalBase {'),
    code.replace('class Sample {','namespace External { class Sample {')+'}',
    code.replace('class Sample {','class Sample<String> {'),
    code.replace('class Sample {','class Sample : ExternalBase<int> {').replace('String text', 'int a=1; int b=2; int c=3; int d=4; int e=5; String text'),
    code.replace('String text = "status"', 'String text = Request.Query["cmd"]'),
  ]) assert.equal(isConstantCSharpSink({code:unsafe,line:4,ruleId:'CS-CMDI-001'}),false,unsafe);
});

test('generic inherited String types cannot bypass alias rejection through padding', () => {
  const code=`using String = string;
class Sample : ExternalBase<int> {
 void Run() { int a=1; int b=2; int c=3; int d=4; int e=5; String text = "status";
  Process.Start(text + "");
 }
}`;
  assert.equal(isConstantCSharpSink({code,line:3,ruleId:'CS-CMDI-001'}),false);
});

test('scanner retains unsafe twins of multi-argument and branch-only command calls', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-command-proofs-'));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  fs.writeFileSync(path.join(root,'Safe.cs'), `using String = string;
class Safe {
 private String Argument() { String value = "status"; return value; }
 void Run(bool flag) { string shell = "cmd /c ";
  Process.Start("cmd.exe", "/c " + Argument());
  Process.Start(shell + (flag ? "status" : "help"));
 }
}`);
  fs.writeFileSync(path.join(root,'Unsafe.cs'), `class Unsafe {
 void Run(string input, bool flag) { string shell = "cmd /c ";
  Process.Start("cmd.exe", "/c " + input);
  Process.Start(shell + (flag ? "status" : input));
  Process.Start("fixed"); Process.Start(shell + input);
 }
}`);
  const result = await scan(root,{includeTests:true});
  assert.deepEqual(result.findings.filter(f=>f.ruleId==='CS-CMDI-001').map(f=>[f.file,f.line]),[
    ['Unsafe.cs',3],['Unsafe.cs',4],['Unsafe.cs',5],
  ]);
});

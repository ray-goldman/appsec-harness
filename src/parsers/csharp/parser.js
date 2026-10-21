'use strict';

const { tokenizeCSharp } = require('./lexer');
const CONTROL = new Set(['if', 'while', 'for', 'foreach', 'switch', 'catch', 'using', 'lock', 'fixed', 'nameof', 'typeof', 'checked', 'unchecked']);
const TYPE = new Set(['class', 'struct', 'interface', 'record']);

function parseCSharp(source) {
  const lexed = tokenizeCSharp(source), { tokens } = lexed, errors = [...lexed.errors], declarations = [], methods = [];
  const stack = [], pairs = new Map();
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (['(', '{', '['].includes(t.text)) stack.push(i);
    else if ([')', '}', ']'].includes(t.text)) {
      const open = stack.pop();
      if (open === undefined || !({ ')': '(', '}': '{', ']': '[' })[t.text] || tokens[open].text !== ({ ')': '(', '}': '{', ']': '[' })[t.text]) {
        errors.push({ message: 'unbalanced delimiter', start: t.start }); continue;
      }
      pairs.set(open, i); pairs.set(i, open);
    }
  }
  for (const open of stack) errors.push({ message: 'unclosed delimiter', start: tokens[open].start });
  const isId = t => t && t.kind === 'identifier';
  for (let i = 0; i < tokens.length - 1; i++) {
    if (TYPE.has(tokens[i].text) && isId(tokens[i + 1])) declarations.push({ kind: tokens[i].text, name: tokens[i + 1].text.replace(/^@/, ''), start: tokens[i].start, end: tokens[i + 1].end });
    if (tokens[i].text === 'unsafe' || tokens[i].text === 'goto') errors.push({ message: `unsupported ${tokens[i].text}`, start: tokens[i].start });
  }
  const lineAt = offset => source.slice(0, offset).split(/\r?\n/).length;
  const addStatement = (list, kind, index, endIndex = index) => {
    const a = tokens[index], b = tokens[endIndex];
    if (a && b) list.push({ kind, start: a.start, end: b.end, startLine: lineAt(a.start), endLine: lineAt(b.end) });
  };
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text !== '(' || !pairs.has(i)) continue;
    const close = pairs.get(i), nameToken = tokens[i - 1], name = nameToken?.text?.replace(/^@/, '');
    if (!isId(nameToken) || CONTROL.has(name) || tokens[close + 1]?.text === '=>' || tokens[close + 1]?.text === '.') continue;
    let body = close + 1;
    while (['where'].includes(tokens[body]?.text)) body++;
    if (tokens[body]?.text !== '{' || !pairs.has(body)) continue;
    // A declaration has a type/member prefix and is not a call expression or control construct.
    const prefix = tokens.slice(Math.max(0, i - 7), i).map(t => t.text);
    if (!prefix.some(x => ['public','private','protected','internal','static','virtual','override','async','partial','new','sealed','abstract','void','string','int','bool','Task','var'].includes(x)) &&
        !declarations.some(d => d.name === name)) continue;
    const endIndex = pairs.get(body), statements = [];
    const parameters = [];
    let paramDepth = 0, paramStart = i + 1;
    for (let j = i + 1; j <= close; j++) {
      const txt = tokens[j]?.text;
      if (['(', '[', '<'].includes(txt)) paramDepth++;
      else if ([')', ']', '>'].includes(txt)) paramDepth--;
      if ((txt === ',' && paramDepth === 0) || j === close) {
        const part = tokens.slice(paramStart, j), last = [...part].reverse().find(t => t.kind === 'identifier');
        if (last) parameters.push({ name: last.text.replace(/^@/, ''), type: part.slice(0, part.indexOf(last)).map(t => t.text).join('') || null, start: part[0].start, end: part.at(-1).end });
        paramStart = j + 1;
      }
    }
    let depth = 0;
    for (let j = body + 1; j < endIndex; j++) {
      const tok = tokens[j];
      if (['if','switch','try','catch','finally','for','foreach','while','using','return','throw','break','continue'].includes(tok.text)) {
        addStatement(statements, tok.text, j);
      }
      if (tok.text === '=' && depth === 0) addStatement(statements, 'assignment', j - 1, j);
      if (['{','(' ,'['].includes(tok.text)) depth++;
      else if (['}',')',']'].includes(tok.text)) depth--;
    }
    const declarationStart = Math.max(0, tokens[Math.max(0, i - 8)]?.start ?? nameToken.start);
    const prefixText = tokens.slice(Math.max(0, i - 8), i).map(t => t.text);
    const visibility = ['public','protected','internal','private'].find(v => prefixText.includes(v)) || 'private';
    methods.push({ name, start: nameToken.start, end: tokens[endIndex].end, declarationStart, startLine: lineAt(nameToken.start), endLine: lineAt(tokens[endIndex].end), bodyStart: tokens[body].start, bodyEnd: tokens[endIndex].end, parameters, visibility, statements });
    i = body;
  }
  return {
    complete: errors.length === 0,
    declarations,
    methods,
    regions: lexed.regions,
    errors,
    coverage: { discoveredMethods: methods.length, parsedMethods: errors.length ? 0 : methods.length, methodRatio: methods.length ? (errors.length ? 0 : 1) : null },
  };
}

module.exports = { parseCSharp };

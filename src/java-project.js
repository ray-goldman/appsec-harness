'use strict';
const { indexJavaFile } = require('./java-methods');

function buildJavaProjectIndex(files, { complete = true, callArgs } = {}) {
  const byFile = new Map(), classes = new Map();
  let bytes = 0, reflective = !complete;
  if (files.length > 50000) complete = false;
  for (const source of files) {
    bytes += Buffer.byteLength(source.raw);
    if (bytes > 100 * 1024 * 1024) { complete = false; break; }
    const index = indexJavaFile(source);
    if (/\b(?:reflect|invoke|invokeExact|invokeWithArguments|getDeclaredMethod|getDeclaredMethods|getMethod|getMethods|MethodHandle|MethodHandles|Lookup|setAccessible|trySetAccessible)\b/.test(index.mask)) reflective = true;
    let cachedFilter;
    const entry = { index, get filter() {
      if (!cachedFilter) cachedFilter = require('./java-constants').constantSinkFilter(source.code, callArgs, source.raw, { file: source.file, project });
      return cachedFilter;
    } };
    byFile.set(source.file, entry);
    for (const name of index.declaredClasses) classes.set(name, classes.has(name) ? null : entry);
    // Unicode preprocessing can introduce declarations hidden by comments.
    if (/\\u+[0-9a-fA-F]{4}/.test(source.raw)) complete = false;
  }
  const project = {
    complete, reflective: reflective || !complete, byFile, classes,
    resolve(caller, owner) {
      if (!complete) return null;
      let qualified = owner;
      if (!owner.includes('.')) {
        if (caller.imports.has(owner)) qualified = caller.imports.get(owner);
        else qualified = [caller.package, owner].filter(Boolean).join('.');
      }
      const found = classes.get(qualified);
      return found?.index.complete ? found : null;
    },
  };
  return project;
}

module.exports = { buildJavaProjectIndex };

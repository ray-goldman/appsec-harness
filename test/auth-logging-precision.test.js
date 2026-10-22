'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {scan}=require('../src/engine');
async function findings(t, source, name='client.js') {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-auth-logging-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,name),source);
 return (await scan(root,{includeTests:true})).findings.filter(f=>f.ruleId==='PROJ-LOGGING-001');
}
test('auth logging heuristic ignores supported direct JavaScript navigation literals',async t=>{
 for(const code of [
  `function refresh() { if (response.status === 401) { location.href = '/login'; return; } }`,
  `window.location.href = '/login';`,
 ]) assert.equal((await findings(t,code)).length,0,code);
});
test('auth logging heuristic keeps identifiers, dispatch, comparisons and executable strings',async t=>{
 for(const code of [
  `function login(user, supplied) { return check(user, supplied); }`,
  `if (bcrypt.compare(supplied, stored)) session.active = true;`,
  `auth['login'](user, supplied);`,
  `const routes = {'login': (req,res) => verify(req,res)};`,
  `app.post('/login', (req,res) => verify(req,res));`,
  `if (supplied === 'login') session.active = true;`,
  `const method = 'login'; auth[method](user, supplied);`,
  `eval('login(user, supplied)');`,
  `eval(input || 'login(user, supplied)');`,
  `auth[method || 'login'](user, supplied);`,
  `handler.action = request.action || 'login'; handler[handler.action](request, response);`,
  `handler.action = request.action ?? 'authenticate'; handler[handler.action](request, response);`,
  `state.prompt = result.prompt || 'login:'; state.mode = result.mode || 'login';`,
  `panel.textContent = 'login';`,
  `eval(location.href = 'login(user, supplied)');`,
  `const location = {set href(value){ dispatch(value); }}; location.href='/login';`,
  `function run(location){ location.href='/login'; }`,
  `Object.defineProperty(window, 'location', {value: custom}); window.location.href='/login';`,
  `window.location = {set href(value){ dispatch(value); }}; window.location.href='/login';`,
  `delete window.location; window.location.href='/login';`,
  `function run(scope) { with (scope) { location.href = '/login'; } }`,
  `location.href = 'javascript:login(user, supplied)';`,
  `window.location.href = 'JaVaScRiPt:authenticate(user, supplied)';`,
  `location.href = '\\tjavascript:login(user, supplied)';`,
  `location.href = 'data:text/html,<script>login()</script>';`,
  `const g=this; g['location']=custom; location.href='/login';`,
  `global['location']=custom; location.href='/login';`,
  `const g=(() => {}).constructor('return this')(); g['location']=custom; location.href='/login';`,
  `const key = 'constructor'; location.href='/login';`,
  `const key='con'+'structor'; const g=(()=>{})[key]('return this')(); g['lo'+'cation']=custom; location.href='/login';`,
  `const key='con'+'structor'; const factory=(()=>{})[key]; const g=factory('return this')(); location.href='/login';`,
  'panel.textContent = `${login(user, supplied)}`;',
  `panel.textContent = 'login'; auth.authenticate(user, supplied);`,
  `panel.textContent = 'login'; unknown !!! syntax`,
  `panel.textContent = 'login';`+' '.repeat(200001),
 ]) assert.ok((await findings(t,code)).length,code.slice(0,150));
});
test('existing logging heuristic remains unchanged including its known data-string limitation',async t=>{
 assert.equal((await findings(t,`function login(user, supplied) { logger.info('attempt'); return verify(user,supplied); }`)).length,0);
 assert.equal((await findings(t,`function login(user, supplied) { return verify(user,supplied); } const text = 'logger.info';`)).length,0);
 assert.equal((await findings(t,`function login(user, supplied) { eval("logger.info('attempt')"); return verify(user,supplied); }`)).length,0);
});
test('unsupported TypeScript keeps literal auth hints',async t=>{
 assert.ok((await findings(t,`const status: string = 'login';`,'client.ts')).length);
});

test('parser absence and structural budgets retain auth literal hints',async t=>{
 const source = `location.href = '/login';`;
 assert.ok((await findings(t,source+'\n'+'0;'.repeat(25000))).length);
 assert.ok((await findings(t,source+'\n'+'['.repeat(170)+'0'+']'.repeat(170)+';')).length);
 const Module=require('node:module'),original=Module._load;
 try {
  Module._load=function(id,...args){if(id==='./parsers/acorn')throw Error('Parser unavailable');return original.call(this,id,...args);};
  assert.ok((await findings(t,source)).length);
 } finally {Module._load=original;}
});
test('other-language auth evidence is unchanged including docstrings',async t=>{
 assert.ok((await findings(t,'def probe():\n    """Never authenticate in this diagnostic."""\n    return 1\n','probe.py')).length);
});

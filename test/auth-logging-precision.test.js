'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {scan}=require('../src/engine');
async function findings(t, source, name='client.js', extra={}) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-auth-logging-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,name),source);
 for(const [file,code] of Object.entries(extra)) fs.writeFileSync(path.join(root,file),code);
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
test('Python documentation-only auth hints are refined',async t=>{
 assert.equal((await findings(t,'def probe():\n    """Never authenticate in this diagnostic."""\n    return 1\n','probe.py')).length,0);
});

const consoleAuth = body => `using System;
class Server {
 private bool login(string password) {
  ${body}
 }
}`;

test('C# console authentication outcomes on every normal exit count as visible logging',async t=>{
 for(const body of [
  'if (password == "expected") { Console.WriteLine("Authentication success"); return true; } else { Console.WriteLine("Auth failed"); return false; }',
  'if (password == "expected") { Console.WriteLine($"User {password.Length} authenticated successfully"); } else { Console.WriteLine($"Auth failed for user {password.Length}"); } return true;',
 ]) assert.equal((await findings(t,consoleAuth(body),'Server.cs')).length,0,body);
});

test('C# console evidence supports request-derived reads and fails closed on missing parser or source budgets',async t=>{
 const source=`using System;
 class Server {
  bool login(Request request) {
   var reader = new Reader(request.Body);
   string body = reader.Read();
   var account = Decode(body);
   if (account != null && (account.Name == "member" || account.Name == "operator")) {
    Console.WriteLine($"User {account.Name} authenticated successfully"); return true;
   } else { Console.WriteLine($"Auth failed for user {account.Name}"); return false; }
  }
 }`;
 assert.equal((await findings(t,source,'Server.cs')).length,0);
 assert.ok((await findings(t,source+' '.repeat(200001),'Server.cs')).length);
 const Module=require('node:module'),original=Module._load;
 try {
  Module._load=function(id,...args){if(id==='./csharp-auth-logging')throw Error('Parser unavailable');return original.call(this,id,...args);};
  assert.ok((await findings(t,source,'Server.cs')).length);
 } finally {Module._load=original;}
 const {csharpConsoleAuthEvidence}=require('../src/csharp-auth-logging');
 assert.equal(csharpConsoleAuthEvidence(source,{files:[],complete:false}),false);
 assert.equal(csharpConsoleAuthEvidence(source,{files:Array.from({length:1001},()=>({lang:'csharp',code:''})),complete:true}),false);
});

test('C# console evidence retains incomplete, unrelated and unsupported logging flows',async t=>{
 for(const body of [
  'return password == "expected";',
  'Console.WriteLine("Server started"); return password == "expected";',
  'if (password == "expected") { Console.WriteLine("Auth success"); return true; } return false;',
  'if (password == "expected") { Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); } return false;',
  'if (false) { Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); } return false;',
  'if (false) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'bool enabled = false; if (enabled) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'return false; Console.WriteLine("Auth success"); Console.WriteLine("Auth failed");',
  'done: return false; Console.WriteLine("Auth success"); Console.WriteLine("Auth failed");',
  'if (password.Length > 0) done: return false; Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); return false;',
  'if (1 == 2) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'if (null != null) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'var enabled = 0; if (enabled == 1) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'if (password != password) { Console.WriteLine("Auth success"); return true; } Console.WriteLine("Auth failed"); return false;',
  'Console.WriteLine("Authentication success or failure is not recorded"); return false;',
  'string text = "Console.WriteLine(\\"Auth success\\"); Console.WriteLine(\\"Auth failed\\");"; return false;',
  '/* Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); */ return false;',
  'if (password == "expected") return true; Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); return false;',
  'Action callback = () => { Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); }; return false;',
  'try { Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); } catch { } return false;',
 ]) assert.ok((await findings(t,consoleAuth(body),'Server.cs')).length,body);
 const complete=consoleAuth('Console.WriteLine("Auth success"); Console.WriteLine("Auth failed"); return false;');
 assert.ok((await findings(t,complete.replace('class Server','class Server : ExternalBase'),'Server.cs')).length);
 assert.ok((await findings(t,complete.replace('class Server','class Server<Console>'),'Server.cs')).length);
 assert.ok((await findings(t,complete.replace('using System;','using Console = Custom.Console;'),'Server.cs')).length);
 assert.ok((await findings(t,complete.replace('private bool login','private bool other')+' class Unlogged { bool login(string p) { return false; } }','Server.cs')).length);
 for(const member of [
  'bool authenticate(bool ok) => ok;', 'bool authenticate<T>(bool ok) { return ok; }', 'bool IAuth.authenticate(bool ok) => ok;',
  'bool check_password(string p) { return false; }', 'bool password_verify(string p) { return false; }',
  'public Func<string, bool> authenticate = password => password == "expected";',
  'public bool authenticate { get { return false; } }', 'public bool authenticate => false;',
  'public Func<string, bool> authenticateUser = password => password == "expected";',
  'public bool authenticateUser { get { return false; } }',
 ]) {
  assert.ok((await findings(t,complete.replace('class Server {','class Server { '+member),'Server.cs')).length,member);
 }
 for(const shadow of [
  'class Console { public static void WriteLine(string message) {} }',
  'class @Console { public static void WriteLine(string message) {} }',
  'class Conso\u200cle { public static void WriteLine(string message) {} }',
  'class Conso\ufeffle { public static void WriteLine(string message) {} }',
  'global using Console = Sink; class Sink { public static void WriteLine(string message) {} }',
 ]) {
  assert.ok((await findings(t,complete,'Server.cs',{'Other.cs':shadow})).length,shadow);
  assert.ok((await findings(t,complete+' '+shadow,'Server.cs')).length,shadow);
 }
 assert.ok((await findings(t,complete.replace('string password','dynamic @Console, string password'),'Server.cs')).length);
 assert.ok((await findings(t,complete.replace('string password','dynamic Conso\u200cle, string password'),'Server.cs')).length);
 assert.ok((await findings(t,complete.replace('string password','dynamic Conso\ufeffle, string password'),'Server.cs')).length);
});

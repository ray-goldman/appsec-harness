'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {scan}=require('../src/engine');
async function hits(t,source,rule,extra={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-py-logging-'));
 t.after(()=>{assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
 fs.writeFileSync(path.join(root,'app.py'),source);
 for(const [name,text]of Object.entries(extra)){fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});fs.writeFileSync(path.join(root,name),text);}
 return (await scan(root,{includeTests:true})).findings.filter(f=>f.ruleId===rule);
}
const imports='from flask import request\nimport logging\nlogger = logging.getLogger(__name__)\n';
test('Python lifecycle audit messages distinguish source address from credentials',async t=>{
 for(const line of [
  'logger.info("Account password changed from %s", request.remote_addr or "unknown")',
  'logger.info("Initial dashboard password configured from %s", request.remote_addr or "unknown")',
  'logger.info("Password changed")',
 ])assert.equal((await hits(t,imports+line,'PY-LOG-001')).length,0,line);
});
test('Python logging retains secret values, extra arguments and unknown expressions',async t=>{
 for(const line of [
  'logger.info("Account password changed from %s", password)',
  'logger.info("Account password changed from %s", request.form["password"])',
  'logger.info("Account password changed from %s", request.remote_addr or password)',
  'logger.info("Password changed", extra={"token": token})',
  'logger.info(f"Password changed {password}")',
  'logger.info("Password changed from %s" % token)',
  'logger.info("Password changed from {}".format(token))',
  'logger.info("Password changed: embedded-value")',
  'logger.info("Password changed"); print(password)',
  'logger.info("Password changed"); logger.error(token)',
  'LOGGER = logger\nlogger.info("Password changed"); LOGGER.error(password)',
  'logger.info("Password changed"); loggerinfo(password)',
  'logger.info("Password changed"); f"{logger.error(password)}"',
  'logger.info("Password changed"); F"{LOGGER.ERROR(password)}"',
  'print(password)',
  'logger.info("Password changed", *values)',
 ])assert.ok((await hits(t,imports+line,'PY-LOG-001')).length,line);
});
test('Python logging retains shadowed and mutable Flask request bindings',async t=>{
 const safe='logger.info("Password changed from %s", request.remote_addr or "unknown")\n';
 for(const change of [
  'request = custom\n',
  'request.remote_addr = password\n',
  'request.environ["REMOTE_ADDR"] = password\n',
  'from other import *\n',
  'setattr(request, "remote_addr", password)\n',
  'globals()["request"] = custom\n',
  'def replace(request):\n    pass\n',
  'for request in values:\n    pass\n',
  'from flask import Request\nRequest.remote_addr = property(lambda self: self.headers.get("Authorization"), lambda self, value: None)\n',
  'app.request_class = custom\n',
  '(request.remote_addr, other) = (password, 0)\n',
  'for request.remote_addr in values:\n    pass\n',
  'from flask import request; request = custom\n',
  '(\n request.remote_addr,\n other\n) = (password, 0)\n',
  'for (\n request.remote_addr,\n other\n) in values:\n    pass\n',
  'with manager(password) as request.remote_addr:\n    pass\n',
  'async with manager(password) as (\n request.remote_addr,\n other\n):\n    pass\n',
  'request.remote_addr <<= custom\n',
 ]) assert.ok((await hits(t,imports+change+safe,'PY-LOG-001')).length,change);
 assert.ok((await hits(t,imports+safe,'PY-LOG-001',{'flask.py':'request = custom\n'})).length);
});
test('Python plain docstrings do not establish authentication code',async t=>{
 for(const code of [
  '"""Do not authenticate in this utility."""\nvalue = 1\n',
  'def inspect_radio():\n    """Never authenticate or inject frames."""\n    return 1\n',
  'def inspect_radio():\n    """Do not authenticate.\n    Read diagnostics only.\n    """\n    return 1\n',
 ])assert.equal((await hits(t,code,'PROJ-LOGGING-001')).length,0,code);
});
test('Python docstring handling preserves executable and ambiguous authentication evidence',async t=>{
 for(const code of [
  'def login(user):\n    """This function authenticates a user."""\n    return verify(user)\n',
  'def inspect_radio():\n    f"Do not {authenticate(user)}"\n',
  'def inspect_radio():\n    """Do not authenticate."""; authenticate(user)\n',
  'def inspect_radio():\n    note = "authenticate"\n',
  'def inspect_radio():\n    """authenticate(user)"""\nexec(inspect_radio.__doc__)\n',
  '@consume(\n)\ndef inspect_radio():\n    """authenticate(user)"""\n',
  '@consume\n# comment\ndef inspect_radio():\n    """authenticate(user)"""\n',
  'class Service(metaclass=consume):\n    def inspect_radio(self):\n        """authenticate(user)"""\n',
  'text = """\ndef inspect_radio():\n    "authenticate"\n"""\n',
  'def inspect_radio():\n    """authenticate\n',
 ])assert.ok((await hits(t,code,'PROJ-LOGGING-001')).length,code);
});
test('Python lexical bounds retain original logging and auth hints',async t=>{
 const line='logger.info("Password changed")\n';
 assert.ok((await hits(t,line+' '.repeat(200001),'PY-LOG-001')).length);
 assert.ok((await hits(t,line+'"unterminated\n','PY-LOG-001')).length);
 assert.ok((await hits(t,'"""authenticate"""\n'+'['.repeat(70)+'0'+']'.repeat(70),'PROJ-LOGGING-001')).length);
 assert.ok((await hits(t,line+'0;'.repeat(25000),'PY-LOG-001')).length);
});

test('Python source-address profile requires complete source indexing',()=>{
 const {createPythonLoggingProof}=require('../src/python-log-evidence');
 const code=imports+'logger.info("Password changed from %s", request.remote_addr)';
 assert.equal(createPythonLoggingProof(code,{entries:new Map(),indexedComplete:false})(3),false);
 assert.equal(createPythonLoggingProof(code,{entries:new Map(),indexedComplete:true})(3),true);
});

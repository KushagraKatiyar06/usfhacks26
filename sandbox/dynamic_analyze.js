/**
 * UseProtechtion — Dynamic JS Interceptor
 * Runs JS/VBS malware with fully stubbed Windows APIs.
 * Nothing actually executes — every dangerous call is intercepted,
 * logged, and returned as structured JSON.
 *
 * Usage: node dynamic_analyze.js <filepath>
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const target = process.argv[2];
if (!target) { console.error('Usage: node dynamic_analyze.js <filepath>'); process.exit(1); }

// ── Capture store ─────────────────────────────────────────────────────────────

const captured = {
  objects_created:  [],   // COM class names instantiated
  shell_commands:   [],   // WScript.Shell.Run / .Exec calls
  file_ops:         [],   // FileExists, Write, Delete, etc.
  network:          [],   // XMLHttp open, DNS, etc.
  registry:         [],   // RegRead / RegWrite
  eval_chains:      [],   // eval() calls (multi-layer decoded strings)
  decode_ops:       [],   // base64 / unicode decode attempts
  processes:        [],   // process spawn entries for the graph
  errors:           [],
};

let evalDepth = 0;
const MAX_EVAL_DEPTH = 6;

// ── Helpers ───────────────────────────────────────────────────────────────────

function truncate(s, n = 300) { return String(s).slice(0, n); }

function logProc(parent, child, cmd) {
  captured.processes.push({ parent, child, cmd: truncate(cmd, 500), color: 'red' });
}

// ── Windows API stubs ─────────────────────────────────────────────────────────

function makeStream() {
  const buf = [];
  return {
    Type: 1, Position: 0, Size: 0, Charset: 'utf-8',
    Open()  {},
    Close() {},
    Write(data) {
      const s = typeof data === 'string' ? data : Buffer.from(data).toString('hex');
      captured.file_ops.push({ op: 'STREAM_WRITE', preview: truncate(s) });
      buf.push(s);
    },
    WriteText(t) {
      captured.file_ops.push({ op: 'STREAM_WRITE_TEXT', preview: truncate(t) });
      buf.push(t);
    },
    SaveToFile(p) {
      captured.file_ops.push({ op: 'SAVE_TO_FILE', path: p });
    },
    LoadFromFile(p) {
      captured.file_ops.push({ op: 'LOAD_FROM_FILE', path: p });
    },
    ReadText()  { return buf.join(''); },
    Read()      { return buf.join(''); },
    CopyTo()    {},
  };
}

function makeFileSystem() {
  return {
    FileExists(p)   { captured.file_ops.push({ op: 'FILE_EXISTS',   path: p }); return false; },
    FolderExists(p) { captured.file_ops.push({ op: 'FOLDER_EXISTS', path: p }); return false; },
    DeleteFile(p)   { captured.file_ops.push({ op: 'DELETE_FILE',   path: p }); },
    DeleteFolder(p) { captured.file_ops.push({ op: 'DELETE_FOLDER', path: p }); },
    CopyFile(s, d)  { captured.file_ops.push({ op: 'COPY_FILE', src: s, dst: d }); },
    MoveFile(s, d)  { captured.file_ops.push({ op: 'MOVE_FILE', src: s, dst: d }); },
    GetFile(p)      { captured.file_ops.push({ op: 'GET_FILE', path: p }); return { Size: 0, Path: p }; },
    GetFolder(p)    { return { Files: { Count: 0 }, SubFolders: { Count: 0 } }; },
    GetSpecialFolder(n) { return { Path: ['C:\\Windows\\System32', 'C:\\Windows\\Temp', 'C:\\Windows'][n] ?? 'C:\\Windows' }; },
    GetTempName()   { return 'tmp' + Math.random().toString(36).slice(2) + '.tmp'; },
    BuildPath(a, b) { return a + '\\' + b; },
    CreateTextFile(p) {
      captured.file_ops.push({ op: 'CREATE_TEXT_FILE', path: p });
      return { Write(t) { captured.file_ops.push({ op: 'TEXT_WRITE', path: p, preview: truncate(t) }); }, Close() {}, WriteLine(t) {} };
    },
    OpenTextFile(p) {
      captured.file_ops.push({ op: 'OPEN_TEXT_FILE', path: p });
      return { ReadAll() { return ''; }, ReadLine() { return ''; }, Close() {}, AtEndOfStream: true };
    },
  };
}

function makeXmlHttp() {
  let _method = '', _url = '';
  return {
    open(method, url)   { _method = method; _url = url; captured.network.push({ op: 'OPEN', method, url }); },
    send(body)          { captured.network.push({ op: 'SEND', method: _method, url: _url, body: truncate(body ?? '') }); },
    setRequestHeader()  {},
    get responseText()  { return ''; },
    get responseBody()  { return ''; },
    get status()        { return 200; },
    get readyState()    { return 4; },
    onreadystatechange: null,
  };
}

function makeXmlDom() {
  let _xml = '';
  return {
    async: false,
    loadXML(x)  { _xml = x; captured.network.push({ op: 'LOAD_XML', preview: truncate(x) }); },
    load(url)   { captured.network.push({ op: 'LOAD_URL', url }); },
    getElementsByTagName() { return { item() { return null; }, length: 0 }; },
    selectNodes()       { return { length: 0, item() { return null; } }; },
    selectSingleNode()  { return null; },
    get text()          { return ''; },
    get xml()           { return _xml; },
    setProperty()       {},
  };
}

function makeShell() {
  return {
    Run(cmd, style, wait) {
      captured.shell_commands.push({ op: 'RUN', cmd: truncate(cmd, 1000) });
      logProc('WScript.Shell', detectChild(cmd), cmd);
      return 0;
    },
    Exec(cmd) {
      captured.shell_commands.push({ op: 'EXEC', cmd: truncate(cmd, 1000) });
      logProc('WScript.Shell', detectChild(cmd), cmd);
      return { StdOut: { ReadAll() { return ''; }, AtEndOfStream: true }, StdErr: { ReadAll() { return ''; } }, ExitCode: 0 };
    },
    ExpandEnvironmentStrings(s) {
      return s.replace(/%([^%]+)%/g, (_, v) => ({
        WINDIR: 'C:\\Windows', TEMP: 'C:\\Windows\\Temp',
        TMP: 'C:\\Windows\\Temp', APPDATA: 'C:\\Users\\Public\\AppData\\Roaming',
        PUBLIC: 'C:\\Users\\Public', USERPROFILE: 'C:\\Users\\Public',
        SYSTEMROOT: 'C:\\Windows',
      }[v.toUpperCase()] ?? v));
    },
    RegRead(key)        { captured.registry.push({ op: 'REG_READ',  key }); return ''; },
    RegWrite(key, val)  { captured.registry.push({ op: 'REG_WRITE', key, val: truncate(String(val)) }); },
    RegDelete(key)      { captured.registry.push({ op: 'REG_DELETE', key }); },
    Popup()             { return 1; },
    SendKeys()          {},
    AppActivate()       { return false; },
  };
}

function detectChild(cmd) {
  const c = cmd.toLowerCase();
  if (c.includes('powershell')) return 'powershell.exe';
  if (c.includes('cmd'))        return 'cmd.exe';
  if (c.includes('wscript'))    return 'wscript.exe';
  if (c.includes('cscript'))    return 'cscript.exe';
  if (c.includes('mshta'))      return 'mshta.exe';
  if (c.includes('regsvr32'))   return 'regsvr32.exe';
  if (c.includes('rundll32'))   return 'rundll32.exe';
  return 'subprocess.exe';
}

// ── ActiveXObject / CreateObject dispatcher ───────────────────────────────────

function createObject(cls) {
  const cl = (cls || '').toLowerCase();
  captured.objects_created.push(cls);

  if (cl.includes('adodb.stream'))                 return makeStream();
  if (cl.includes('scripting.filesystemobject'))   return makeFileSystem();
  if (cl.includes('wscript.shell') || cl === 'shell.application') return makeShell();
  if (cl.includes('xmlhttp') || cl.includes('serverxmlhttp'))     return makeXmlHttp();
  if (cl.includes('xmldom') || cl.includes('msxml'))              return makeXmlDom();
  if (cl.includes('scripting.dictionary')) {
    const d = {};
    return { Add: (k,v)=>{ d[k]=v; }, Item: (k)=>d[k]??'', Exists: (k)=>k in d, Count: ()=>Object.keys(d).length, Keys: ()=>Object.keys(d), Items: ()=>Object.values(d), Remove: (k)=>{ delete d[k]; } };
  }
  // Generic proxy — catch any property access
  return new Proxy({}, {
    get(_, p) { return typeof p === 'string' ? (() => '') : undefined; },
    set() { return true; },
  });
}

// ── WScript global ────────────────────────────────────────────────────────────

global.WScript = {
  CreateObject:  createObject,
  GetObject:     createObject,
  Sleep:         () => {},
  Echo:          (m) => captured.eval_chains.push(truncate(m)),
  Quit:          () => {},
  ScriptFullName: target,
  ScriptName:    path.basename(target),
  FullName:      'C:\\Windows\\System32\\wscript.exe',
  Path:          'C:\\Windows\\System32',
  Version:       '5.8',
  Arguments:     { Count: 0, Item: () => '', length: 0 },
  StdOut:        { Write: () => {}, WriteLine: () => {} },
  StdErr:        { Write: () => {}, WriteLine: () => {} },
  StdIn:         { ReadLine: () => '', AtEndOfStream: true },
  Interactive:   false,
};

global.ActiveXObject = function(cls) { return createObject(cls); };
global.GetObject     = createObject;

// ── Intercept eval ────────────────────────────────────────────────────────────

const _realEval = global.eval;
global.eval = function interceptedEval(code) {
  const s = String(code);
  evalDepth++;
  captured.eval_chains.push({ depth: evalDepth, preview: truncate(s) });

  // Try to detect base64 / unicode decoding
  if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(s.trim())) {
    try {
      const dec = Buffer.from(s.trim(), 'base64').toString('utf8');
      captured.decode_ops.push({ type: 'base64', preview: truncate(dec) });
    } catch (_) {}
  }

  let result;
  if (evalDepth <= MAX_EVAL_DEPTH) {
    try { result = _realEval(s); } catch (e) { captured.errors.push(`eval[${evalDepth}]: ${e.message}`); }
  }
  evalDepth--;
  return result;
};

// ── String decode helpers (malware commonly uses these) ───────────────────────

global.atob = (s) => {
  const dec = Buffer.from(s, 'base64').toString('latin1');
  captured.decode_ops.push({ type: 'atob', preview: truncate(dec) });
  return dec;
};

global.unescape = (s) => {
  const dec = decodeURIComponent(s.replace(/%u([0-9A-Fa-f]{4})/g, '\\u$1'));
  captured.decode_ops.push({ type: 'unescape', preview: truncate(dec) });
  return dec;
};

// ── Run the malware ───────────────────────────────────────────────────────────

// Add WScript entrypoint as root process
logProc('wscript.exe', path.basename(target), `wscript ${target}`);

let runError = null;
try {
  const code = fs.readFileSync(target, 'utf8');
  global.eval(code);
} catch (e) {
  runError = e.message;
  captured.errors.push(`top-level: ${e.message}`);
}

// ── Output ────────────────────────────────────────────────────────────────────

const output = {
  file: path.basename(target),
  run_error: runError,
  ...captured,
};

process.stdout.write(JSON.stringify(output, null, 2));

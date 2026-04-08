// === Patch 1 ===
const catchAll = {
    get: function(target, prop, receiver) {
        if (prop in target) {
            return target[prop];
        }
        if (typeof prop === 'string') {
             console.log(`[MOCK ATTEMPT] Unhandled property/method access on COM object: ${prop}`);
        }
        return new Proxy(function() {}, catchAll);
    }
};

global.WScript = {
  ScriptName: 'dropper.js',
  ScriptFullName: 'C:\\Users\\Public\\dropper.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit: ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: { length: 0, Item: () => '' },
};

global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);
    const typeLower = type.toLowerCase();

    if (typeLower.includes('wscript.shell')) {
        return new Proxy({
            Run: (cmd, style, wait) => {
                console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
                return 0;
            },
            Exec: (cmd) => {
                console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                return { StdOut: { ReadAll: () => '' }, StdErr: { ReadAll: () => '' }, Status: 0, Terminate: () => {} };
            },
            ExpandEnvironmentStrings: (s) => {
                const expanded = s.replace(/%PUBLIC%/gi, 'C:\\Users\\Public').replace(/%TEMP%/gi, 'C:\\Users\\User\\AppData\\Local\\Temp');
                console.log(`[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ${s} -> ${expanded}`);
                return expanded;
            },
             RegRead: (key) => {
                console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                if (key.includes('Aerofox\\Foxmail')) return 'C:\\Users\\Public\\Foxmail';
                return '1';
            },
        }, catchAll);
    }

    if (typeLower.includes('scripting.filesystemobject')) {
        return new Proxy({
            FileExists: (path) => {
                console.log('[MOCK PATCH] FSO.FileExists: ' + path);
                const p = path.toLowerCase();
                if (p.endsWith('mands.png') || p.endsWith('vile.png') || p.endsWith('mock_script.url')) {
                    return true;
                }
                return false;
            },
            DeleteFile: (path, force) => {
                console.log('[MOCK PATCH] FSO.DeleteFile: ' + path);
            },
            CreateTextFile: (path) => {
                 console.log('[MOCK PATCH] FSO.CreateTextFile: ' + path);
                 return { Write: () => {}, Close: () => {} };
            },
        }, catchAll);
    }
    
    if (typeLower.includes('xmlhttp') || typeLower.includes('winhttp')) {
        return new Proxy({
            open: (method, url, async) => console.log(`[MOCK PATCH] HTTP ${method}: ${url}`),
            send: (data) => console.log('[MOCK PATCH] HTTP send'),
            setRequestHeader: (k, v) => {},
            responseText: '{"status":"success","country":"US","org":"Contoso ISP","hosting":false}',
            responseBody: new Uint8Array([0x4D, 0x5A, 0x90, 0x00]),
            status: 200,
        }, catchAll);
    }
    
    if (typeLower.includes('adodb.stream')) {
        return new Proxy({
            Open: () => console.log('[MOCK PATCH] ADODB.Stream.Open'),
            Write: (d) => console.log('[MOCK PATCH] ADODB.Stream.Write: ' + (d ? d.length : 0) + ' bytes'),
            SaveToFile: (p, mode) => console.log('[MOCK PATCH] ADODB.Stream.SaveToFile: ' + p),
            Close: () => {},
            Type: 1, // adTypeBinary
        }, catchAll);
    }

    return new Proxy({}, catchAll);
};

// === Patch 2 ===
// Fix: Define the global catch-all proxy handler. The crash occurred because this was
// likely re-declared with 'const' instead of being defined once on the global scope.
global.catchAll = {
  get: function(target, prop, receiver) {
    if (prop in target) {
      return Reflect.get(...arguments);
    }
    console.log(`[MOCK PATCH] catchAll: Unhandled property get -> ${String(prop)}`);
    // Return a proxy to a function to handle method calls on undefined properties.
    return new Proxy(() => {}, global.catchAll);
  },
  set: function(target, prop, value, receiver) {
      console.log(`[MOCK PATCH] catchAll: Unhandled property set -> ${String(prop)} = ${value}`);
      target[prop] = value;
      return true;
  }
};


// Pre-stub: Define the base WScript object, as the malware will use it for core
// operations like creating other objects or pausing execution.
global.WScript = {
  ScriptName: 'dropper.js',
  ScriptFullName: 'C:\\Users\\Public\\dropper.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit: ' + (code || 0)),
  CreateObject: (t) => {
    // Defer to the existing ActiveXObject constructor which is defined elsewhere.
    if (typeof ActiveXObject !== 'undefined') {
        return new ActiveXObject(t);
    }
    console.log('[MOCK PATCH] WScript.CreateObject called but ActiveXObject is not defined.');
    return new Proxy({}, global.catchAll);
  },
  Arguments: { length: 0, Item: () => '', Count: () => 0 },
};


// Pre-stub: Implement GetObject for WMI queries (T1047, T1082, T1497). This malware
// heavily relies on WMI for system fingerprinting and VM evasion before execution.
global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);
  if (!path || !path.toLowerCase().includes('winmgmts')) {
      return new Proxy({}, global.catchAll);
  }

  return new Proxy({
    ExecQuery: function(query) {
      console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
      const q = query.toLowerCase();

      if (q.includes('win32_processor'))
        return [{ Name: 'Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz', NumberOfCores: 6, ProcessorId: 'BFEBFBFF000906EA' }];
      if (q.includes('win32_videocontroller'))
        return [{ Name: 'NVIDIA GeForce RTX 2070', VideoProcessor: 'GeForce RTX 2070' }];
      if (q.includes('win32_networkadapterconfiguration'))
        return [{ MACAddress: '00:DE:AD:BE:EF:00', IPEnabled: true, IPAddress: ['192.168.1.55'] }];
      if (q.includes('win32_computersystem'))
        return [{ Manufacturer: 'ASUSTeK COMPUTER INC.', Model: 'ROG STRIX Z390-E GAMING' }];
      if (q.includes('win32_baseboard'))
        return [{ Manufacturer: 'ASUSTeK COMPUTER INC.', Product: 'ROG STRIX Z390-E GAMING', SerialNumber: 'PF91KS481192' }];

      console.log('[MOCK PATCH] WMI ExecQuery: Unhandled query, returning empty set.');
      return []; // Return an empty collection for unhandled queries.
    },
  }, global.catchAll);
};

// === Patch 3 ===
// Fix: Define the central ActiveXObject constructor. This was missing, causing
// WScript.CreateObject to fail. This constructor acts as a factory for the
// various COM objects the malware will request to execute its main logic.
global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);
    const lcaseType = type.toLowerCase();

    // T1059.001 (PowerShell), T1012 (Registry Query) via WScript.Shell
    if (lcaseType.includes('wscript.shell')) {
        return {
            Run: (cmd, style, wait) => {
                console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
                return 0; // Return 0 for success.
            },
            Exec: (cmd) => {
                console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                return {
                    StdOut: {
                        ReadAll: () => ''
                    },
                    StdErr: {
                        ReadAll: () => ''
                    },
                    Status: 0
                };
            },
            ExpandEnvironmentStrings: (s) => {
                console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
                return s.replace(/%PUBLIC%/ig, 'C:\\Users\\Public')
                    .replace(/%TEMP%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp');
            },
            RegRead: (key) => {
                console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                const lcaseKey = key.toLowerCase();
                // Respond to specific checks for credential targets and sandbox artifacts.
                if (lcaseKey.includes('aerofox\\foxmail')) return 'C:\\Program Files\\Foxmail';
                if (lcaseKey.includes('icedragon') || lcaseKey.includes('sbiedll.dll')) return '';
                return '1'; // Default success value.
            },
        };
    }

    // T1497 (VM Evasion) & T1083 (File Discovery) via FileSystemObject
    // Malware checks for its own artifacts and sandbox tools.
    if (lcaseType.includes('scripting.filesystemobject')) {
        return {
            FileExists: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
                const lcasePath = path.toLowerCase();
                // Pretend dropper/sandbox files exist to satisfy malware checks.
                if (lcasePath.endsWith('mands.png') || lcasePath.endsWith('vile.png') || lcasePath.endsWith('mock_script.url') || lcasePath.includes('sbiedll.dll') || lcasePath.includes('snxhk.dll')) {
                    return true;
                }
                return false;
            },
            DeleteFile: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
            },
            GetSpecialFolder: (id) => {
                console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
                if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
                return 'C:\\Users\\Public';
            },
            BuildPath: (path, name) => `${path}\\${name}`,
        };
    }

    // T1071 (Web Protocols) for C2 and anti-VM checks (ip-api.com).
    if (lcaseType.includes('xmlhttp') || lcaseType.includes('winhttp')) {
        return {
            open: (method, url, async) => console.log(`[MOCK PATCH] HTTP ${method}: ${url}`),
            send: (data) => console.log('[MOCK PATCH] HTTP send'),
            setRequestHeader: (k, v) => {},
            status: 200,
            statusText: 'OK',
            // Return response indicating it's NOT a hosting environment to bypass VM check.
            responseText: '{"status":"success","country":"US","org":"Some ISP","hosting":false}',
            responseBody: new Uint8Array(0),
        };
    }

    // Fallback for other COM objects like ADODB.Stream or XMLDOM
    console.log('[MOCK PATCH] Unhandled ActiveXObject type, returning generic mock: ' + type);
    return new Proxy({}, global.catchAll);
};


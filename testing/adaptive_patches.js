// === Patch 1 ===
(function() {
    // Mock for Scripting.FileSystemObject
    function MockFileSystemObject() {
        console.log('[MOCK PATCH] New MockFileSystemObject created.');
        this.Files = []; // To simulate files, if needed later
    }

    MockFileSystemObject.prototype.FileExists = function(path) {
        console.log(`[MOCK PATCH] FileSystemObject.FileExists("${path}") called.`);
        // For now, always return false to indicate the file does not exist,
        // which often prevents deletion or certain operations.
        return false;
    };

    MockFileSystemObject.prototype.DeleteFile = function(path, force) {
        console.log(`[MOCK PATCH] FileSystemObject.DeleteFile("${path}", ${force}) called.`);
        // Simulate successful deletion, or simply do nothing.
        // Returning true/undefined/void can be plausible depending on API.
        return undefined; 
    };

    // Override the global ActiveXObject to return our mock for specific ProgIDs
    var originalActiveXObject = ActiveXObject;
    ActiveXObject = function(progID) {
        console.log(`[MOCK PATCH] ActiveXObject("${progID}") called.`);
        if (progID === "Scripting.FileSystemObject" || progID === "WScript.Shell") { // WScript.Shell is another common one that often uses this
            return new MockFileSystemObject();
        }
        // Fallback to original if not a known mockable object, or return a generic mock
        // depending on desired strictness. Here we pass through or return a catchAll mock.
        if (typeof originalActiveXObject === 'function') {
            try {
                return originalActiveXObject(progID); // Try to call original, might fail in Node.js
            } catch (e) {
                console.log(`[MOCK PATCH] ActiveXObject("${progID}") failed with original constructor: ${e.message}. Returning catchAll.`);
            }
        }
        // If original is not a function or failed, return our generic catch-all
        // This assumes `catchAll` is defined in the initial mock.
        if (typeof catchAll !== 'undefined') {
            return catchAll;
        } else {
            console.warn('[MOCK PATCH] `catchAll` is not defined, returning an empty object for unknown ActiveXObject.');
            return {};
        }
    };
})();

// === Patch 2 ===
// === AUTO-PATCH (iteration 2) ===
// Define ActiveXObject globally if it's not already defined, as it's a browser-specific host object.
// This prevents the ReferenceError when the previous patch tries to capture `originalActiveXObject`.
if (typeof ActiveXObject === 'undefined') {
    console.log('[MOCK PATCH] Defining global ActiveXObject stub to prevent ReferenceError.');
    ActiveXObject = function(progID) {
        console.log(`[MOCK PATCH] Global ActiveXObject stub intercepted call for "${progID}".`);
        // Return a generic mock, similar to how the main ActiveXObject patch handles unknown ProgIDs.
        if (typeof catchAll !== 'undefined') {
            return catchAll;
        } else {
            console.warn('[MOCK PATCH] `catchAll` is not defined, returning an empty object for global ActiveXObject stub.');
            return {};
        }
    };
}

// === Patch 3 ===
if (typeof ActiveXObject === 'undefined') {
    console.log('[MOCK PATCH] Defining global ActiveXObject stub to prevent ReferenceError from undeclared global.');
    ActiveXObject = function(progID) {
        console.log(`[MOCK PATCH] Global ActiveXObject stub intercepted call for "${progID}". Returning generic mock.`);
        // Return a generic mock object. Prioritize `catchAll` if available, otherwise an empty object.
        if (typeof catchAll !== 'undefined') {
            return catchAll;
        } else {
            console.warn('[MOCK PATCH] `catchAll` is not defined, returning an empty object for unknown ActiveXObject.');
            return {};
        }
    };
}

// === Patch 4 ===
if (typeof ActiveXObject === 'undefined') {
    console.log('[MOCK PATCH] Defining global ActiveXObject stub to prevent ReferenceError and complete previous patch intent.');
    ActiveXObject = function(progID) {
        console.log(`[MOCK PATCH] Global ActiveXObject stub intercepted call for "${progID}". Returning catchAll.`);
        return typeof catchAll !== 'undefined' ? catchAll : {};
    };
}

// === Patch 5 ===
if (typeof ActiveXObject === 'undefined') {
    console.log('[MOCK PATCH] Defining global ActiveXObject stub to prevent ReferenceError.');
    ActiveXObject = function(progID) {
        console.log(`[MOCK PATCH] Global ActiveXObject stub intercepted call for "${progID}".`);
        // Return a generic mock object. If `catchAll` is defined by the sandbox, use it.
        if (typeof catchAll !== 'undefined') {
            return catchAll;
        } else {
            // Otherwise, return a basic object that can catch properties and methods
            return new Proxy({}, {
                get: function(target, prop) {
                    console.log(`[MOCK PATCH] Global ActiveXObject stub: Property "${String(prop)}" accessed on "${progID}".`);
                    return function() {
                        console.log(`[MOCK PATCH] Global ActiveXObject stub: Method "${String(prop)}" called on "${progID}".`);
                        return undefined;
                    };
                },
                apply: function(target, thisArg, argumentsList) {
                    console.log(`[MOCK PATCH] Global ActiveXObject stub: Function called on "${progID}".`);
                    return undefined;
                }
            });
        }
    };
}


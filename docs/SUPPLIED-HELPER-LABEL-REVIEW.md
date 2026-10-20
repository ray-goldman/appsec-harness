# Review of supplied JavaScript/Python helper labels

Reviewed before changing the scanner. Input archive SHA-256:
`3dab4cfd405e313ed80093560c3bf17cfb6f4ae5a33902da43a3054af9878c25`.
Files below are relative to `benchmarks/apps/xfile-lab/`. Target code was read
statically; no supplied application or script was executed. Original labels
and benchmark denominators remain unchanged.

| Safe label / sink | Source evidence | Assessment for the labeled mechanism |
|---|---|---|
| `js/routes.js:38`, shell quote | `js/lib/sanitize.js:4` encloses the argument in single quotes and escapes embedded quotes | Conditional on a POSIX shell. The sink does not select one explicitly. Retain warning. |
| `js/routes.js:45`, hostname guard | `js/lib/sanitize.js:10` accepts letters, digits, dots and hyphens; route returns on failure | Prevents shell operators for primitive strings. The validator tests `String(h)` but the sink consumes the original value; general object coercion is not proved stable. Retain until argument types and guard flow are established. Leading options are a separate argument-injection concern. |
| `js/routes.js:50`, configuration constants | `js/lib/config.js` exports literal `REPORT_CMD` and `BACKUP_DIR` values | Safe for the shown literal values; the exported object is mutable and import-time dependencies are incomplete (`db` is absent). Do not assume a read-only module from uppercase names. |
| `js/routes.js:57`, command allow-list | Same module's `COMMANDS` map; missing values rejected | Literal command entries are safe in the shown state. Prototype keys and mutation need separate treatment; do not generalize arbitrary object lookup into a proof. |
| `js/routes.js:69`, basename | `safeName` calls `path.basename(String(f))` | Removes lexical directory components under the platform's path rules. Does not prove symlink confinement or a permitted-file policy. Existing result is unchanged. |
| `js/routes.js:75`, numeric SQL | A local `const` holds the result of built-in `Number`; SQL inserts it in an unquoted numeric position | Accepted for CWE-89 under the ordinary built-in binding. Invalid numbers may cause query errors but do not supply SQL punctuation. Shadowed/replaced conversions must retain warnings. |
| `py/views.py:38`, shell quote | `py/helpers.py:22-23` returns `shlex.quote(s)` | Conditional on a POSIX shell. The sink uses `shell=True` without an executable. Retain warning. |
| `py/views.py:47`, hostname guard | `py/helpers.py:18-19` uses `re.fullmatch`, and failure returns before the command | Accepted for shell-operator injection with the shown guard and unchanged bindings. Leading options remain a separate concern. |
| `py/views.py:56`, argument allow-list | `ALLOWED` holds literal argv lists and sink omits `shell=True` | Shown argv values do not undergo shell parsing. Mutation and command authorization are separate concerns; existing result is unchanged. |
| `py/views.py:70`, basename | `safe_name` returns `os.path.basename(f)` | Lexical filename confinement, with the same symlink/file-policy qualifications as JavaScript. Existing result is unchanged. |
| `py/views.py:77`, numeric SQL | Local `n = int(...)`; the sink formats a single `%d` in a numeric SQL position | Accepted for CWE-89 with the built-in conversion and no intervening reassignment. Shadowed `int`, additional operands and quoted SQL contexts require separate proofs. |

This is a review of the 11 helper-related safe labels, not an adjudication of
all 227 supplied labels. The nearby passthrough, trim-only “sanitizer”, dynamic
query-builder and path-helper vulnerable labels remain negative controls.
No label is changed to make scanner results improve.

Python explicitly limits `shlex.quote` to Unix shells:
[Python shlex documentation](https://docs.python.org/3/library/shlex.html#shlex.quote).
Node's default shell is `/bin/sh` on Unix and `ComSpec` on Windows:
[Node child_process documentation](https://github.com/nodejs/node/blob/main/doc/api/child_process.md).
The host running this scanner is not evidence of a target application's
deployment platform.

The four HTTP allow-list labels identified in the earlier
[supplied-app report](SUPPLIED-APPS.md) still need redirect and deployment
review. They are outside the helper changes in this pass.

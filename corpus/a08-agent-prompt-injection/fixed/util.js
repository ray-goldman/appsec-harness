// Thin wrapper; callers must pass a fixed command list.
function run(args) { return require("child_process").execFileSync(args[0], args.slice(1)); }
module.exports = run;

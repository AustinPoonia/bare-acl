// Separated from index.js for the reason every bare addon does it: `require.addon`
// resolves against the file that calls it, so keeping it here means index.js can be
// moved or bundled without the addon lookup following it.
//
// ## Why the require is guarded, which no other bare addon needs to do
//
// Because this one ships prebuilds for exactly one platform. `require.addon` throws
// when there is no binary for the host, and `lib/custody.js` is kernel code loaded on
// every platform -- so an unguarded require here would turn "this platform has no
// ACLs" into "the kernel does not load on macOS". The binding is therefore allowed to
// be absent, and `index.js#unavailable` turns that absence into a named refusal,
// which is the same shape `custody.js` already uses for the answer it cannot give.
//
// This is deliberately not a fallback to something that pretends: an empty object has
// no `restrict`, so every entry point refuses by name rather than silently reporting
// a boundary it did not write.
let binding = {}

try {
  binding = require.addon('.')
} catch {
  // No prebuild for this host. Not an error here; `unavailable()` reports it.
}

module.exports = binding

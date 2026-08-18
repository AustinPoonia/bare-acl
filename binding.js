/**
 * The addon, or an empty stand-in when this host has no binary for it.
 *
 * Separated from index.js for the reason every bare addon does it: `require.addon`
 * resolves against the file that calls it, so keeping it here means index.js can be
 * moved or bundled without the addon lookup following it.
 *
 * ## Why the require is guarded, which no other bare addon needs to do
 *
 * Because this one ships prebuilds for exactly one platform. `require.addon` throws
 * when there is no binary for the host, and `lib/custody.js` is kernel code loaded on
 * every platform — so an unguarded require would turn "this platform has no ACLs"
 * into "the kernel does not load on macOS". The binding is allowed to be absent and
 * `index.js#unavailable` turns that absence into a named refusal, which is the same
 * shape `custody.js` already uses for an answer it cannot give.
 *
 * @typedef {object} Binding
 * @property {(path: string, inherit: boolean) => void} restrict
 * @property {(path: string) => { aces: number, mask: number, flags: number, protected: boolean, present: boolean, matches: boolean }} inspect
 * @property {() => number} expectedMask
 */

/**
 * Typed as though the addon were always here, and cast into that shape when it is
 * not. That is a deliberate, single lie and this is where it is paid for: the
 * alternative types every member optional, which makes every *call site* in index.js
 * carry a `possibly undefined` guard for a condition `unavailable()` already checks
 * once. One cast with a comment beats six guards that each look like the real check.
 *
 * The runtime property is unaffected — an empty object has no `restrict`, so
 * `unavailable()` sees the absence and every entry point refuses by name.
 *
 * @type {Binding}
 */
let binding = /** @type {Binding} */ ({})

try {
  // `require.addon` is a Bare runtime extension, and the ambient `require` type this
  // file is checked against does not declare it. This repo cannot fix that with its
  // own `vendor.d.ts`: a consumer linking it through `file:` compiles these bytes
  // with *its* tsconfig, so a declaration here would never be seen — which is the
  // rule `platform-diagnostics/vendor.d.ts` states at length. Hence a cast, on the
  // one line that needs it, rather than a declaration file that cannot travel.
  binding = /** @type {Binding} */ (/** @type {any} */ (require).addon('.'))
} catch {
  // No prebuild for this host. Not an error here; `unavailable()` reports it.
}

module.exports = binding

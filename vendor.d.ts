/**
 * Types for the runtime globals this repo's own type-check needs, and nothing else.
 *
 * **Deliberately not referenced from any shipping file**, which is the decision in
 * this file worth stating. `platform-diagnostics/vendor.d.ts` argues it at length and
 * the rule is the same here: a consumer that links this package through `file:`
 * compiles `index.js` and `binding.js` with *its own* tsconfig, so an ambient
 * declaration reached through a `reference` in the source would arrive as a duplicate
 * the consumer cannot edit its way out of. Included by `tsconfig.json` instead, where
 * it covers this repo's check and travels nowhere.
 *
 * That split is also why `binding.js` casts through `any` to reach `require.addon`
 * rather than relying on the declaration below. The declaration fixes *this* repo's
 * check; the cast is what makes the same line survive a consumer whose `require` type
 * is complete but has no `addon` on it — which is exactly what `ArtifactPatform` and
 * `artifact-operator` reported before the cast existed.
 *
 * `tsconfig.json` sets `types: []`, so nothing arrives from `@types` and there is no
 * Node shim in play. That is the point: this package runs on Bare, and a `@types/node`
 * dependency would type-check it against a runtime it never runs on.
 */

/** The CommonJS surface Bare provides. `addon` is Bare's extension. */
declare const require: ((specifier: string) => any) & {
  resolve (specifier: string): string
  addon (specifier: string): any
}

declare const module: { exports: any }

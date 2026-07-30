# Vendored type declarations

Editor-and-`tsc`-only type declarations for the React runtime BunGo embeds. Nothing
here ships to the browser: BunGo bundles its own React, so these files exist purely so
`import React from "react"` resolves during type checking. Vendored rather than
installed because the repo has no npm toolchain — a clone type-checks with no install
step.

`tsconfig.json` wires them in via `compilerOptions.paths` and keeps them out of the
program roots via `exclude`, so they load only when something imports `react`.

## Contents

All files are byte-identical to the published packages. Do not edit them; re-copy
instead (see below).

| Directory | Package | Version |
|-----------|---------|---------|
| `react/` | `@types/react` | 18.3.31 |
| `csstype/` | `csstype` | 3.2.3 |
| `prop-types/` | `@types/prop-types` | 15.7.15 |

`csstype` and `prop-types` are not used directly — `@types/react/index.d.ts` imports
both, so they must resolve for React's own declarations to compile.

`@types/react` is pinned to the 18.x line because BunGo embeds React 18.2.0
(see [docs/bungo.md](../../../docs/bungo.md)). Bumping to a different major here would
describe a React the runtime does not ship. Upstream also publishes `canary.d.ts`,
`experimental.d.ts` and a `ts5.0/` fallback tree; none are vendored, as we target
neither channel and require TypeScript ≥ 5.3.

## Updating

Only needed when BunGo changes its embedded React version.

```sh
cd "$(mktemp -d)"
npm install --no-save @types/react@18 csstype @types/prop-types

V=/path/to/vault3/web/types/vendor
cp node_modules/@types/react/{index,global,jsx-runtime,jsx-dev-runtime}.d.ts \
   node_modules/@types/react/LICENSE                                        "$V/react/"
cp node_modules/csstype/index.d.ts node_modules/csstype/LICENSE             "$V/csstype/"
cp node_modules/@types/prop-types/index.d.ts \
   node_modules/@types/prop-types/LICENSE                                   "$V/prop-types/"
```

Then update the version table above and re-run the type check.

## Type checking

There is no `package.json`, so run `tsc` from anywhere it is available and point it at
the repo config — for example:

```sh
npx --package typescript tsc -p /path/to/vault3/tsconfig.json
```

## Licences

`@types/react` and `@types/prop-types` come from DefinitelyTyped (MIT); `csstype` is
MIT. Each directory retains its upstream `LICENSE` file, which is what those licences
require when redistributing the sources.

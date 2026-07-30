## BunGo Framework Reference (for AI agents)

**See also:** [claude.md](../claude.md) (routing) · [product.md](./product.md) (what Vault3 does) · [security.md](./security.md) (cryptography) · [frontend.md](./frontend.md) (React, styling, `web/`) · [backend.md](./backend.md) (Go, database, auth)

BunGo (Bundler 4 Go) is a fullstack Go web framework that pairs Go server logic with
React (JSX/TSX) views in a single repository. It embeds esbuild and the React runtime
directly into the Go binary — there is no Node.js, npm, package.json, or node_modules.

Go module: github.com/piotr-nierobisz/BunGo

This is a standalone and complete documentation for the BunGo framework.

### Project structure

Every BunGo web application using page routes requires a web directory (commonly
"./web") with the following mandatory sub-directories:

  web/
    layouts/     — Go HTML templates (.gohtml). Required on boot.
    views/       — React entry files (.jsx, .tsx, .js, .ts). Required on boot.
    static/      — Optional. Served as-is at /static/ by the HTTP engine.

When a non-empty webDir is passed to NewServer, the framework panics at startup if
layouts/ or views/ do not exist. If webDir is "" (API-only mode), no directories are
required and no static files are served.


### Core types (root package "bungo")

--- Server ---

  type Server struct {
      Pages          map[string]PageRoute
      APIs           map[string]ApiRoute
      SecurityLayers map[string]SecurityLayer
      Engine         Engine
      WebDir         string
      DefaultLayout  string
  }

  func NewServer(engine Engine, webDir string) *Server

    Creates a Server. Validates that webDir/layouts and webDir/views exist when webDir
    is non-empty (panics on failure).

  func (s *Server) Page(route PageRoute)

    Registers a page route. Panics if Template is empty, if the template file is
    missing on disk, or if the specified Layout or View file does not exist.

  func (s *Server) SetDefaultLayout(path string)

    Sets an optional default layout file for all page routes that do not specify their
    own Layout. The file must exist in webDir/layouts/ (panics otherwise).

  func (s *Server) SetAssetOptimization(enabled bool)

    Toggles production-oriented view asset delivery (default false). When enabled,
    templates reference `/_bungo/*.js` URLs instead of embedding full view bundles
    inline, allowing browser caching and smaller HTML payloads.

  func (s *Server) AssetOptimizationEnabled() bool

    Returns whether optimized JS asset delivery is enabled.

  func (s *Server) Api(route ApiRoute)

    Registers an API route. The internal key is "Version:Method:Path".

  func (s *Server) Security(layer SecurityLayer)

    Registers a named security layer.

  func (s *Server) Serve(port int) error

    Delegates to Engine.Start with address ":port". (Vault3 does not call this —
    see the project conventions at the bottom.)

--- Engine interface ---

  type Engine interface {
      Start(address string, srv *Server) error
  }

--- Request ---

  type Request struct {
      Context  context.Context     // Request scoped context lifecycle
      Headers  map[string]string   // HTTP headers (first value per key)
      Params   map[string]string   // URL query parameters
      Body     []byte              // Raw request body
      Internal map[string]any      // Mutable bag for passing data between security
  }                                // layers and handlers

--- APIResponse ---

  type APIResponse struct {
      StatusCode int
      Body       any         // Marshaled to JSON
      Cookies    []Cookie    // Optional Set-Cookie headers emitted with the response
  }

--- Cookie ---

  type Cookie struct {
      Name     string
      Value    string
      Path     string
      Domain   string
      Expires  time.Time
      MaxAge   int           // 0=unset, >0=seconds, <0=delete now
      Secure   bool
      HttpOnly bool
      SameSite SameSiteMode  // "", "Lax", "Strict", "None"
  }

  bungo.Cookie is transport-neutral. Each Engine (HTTP, HTTPS, AWS Lambda, GCP)
  registers its own cookie converter callback in its constructor:
    - engine.NewHTTPEngine().SetCookieConverter(func(bungo.Cookie) *http.Cookie)
    - engine_aws.NewLambdaEngine().SetCookieConverter(func(bungo.Cookie) string)
  Passing nil restores the engine's default converter.

--- SecurityLayer ---

  type SecurityLayer struct {
      Name    string
      Handler func(req *Request) bool   // false → HTTP 401 Unauthorized
  }

--- PageRoute ---

  type PageRoute struct {
      Path          string
      Template      string               // Required: .gohtml file in layouts/
      Layout        string               // Optional: wrapper .gohtml in layouts/
      View          string               // Optional: .jsx/.tsx/.js/.ts in views/
      SecurityLayer []string             // Names of registered SecurityLayers
      Handler       func(req *Request) (map[string]any, error)
  }

  The Handler runs before rendering. The returned map is:
    - Available as Go template fields in the .gohtml (e.g. {{.PageTitle}}).
    - Serialized to JSON as window.__BUNGO_DATA__ and readable via useBungoData()
      in the React view.

--- ApiRoute ---

  type ApiRoute struct {
      Path          string               // Static path segment, e.g. "/users" — NOT :id / {id} patterns
      Version       string               // e.g. "v1"  → full path: /api/v1/users
      Method        string               // Standard verb only; normalized to uppercase at registration
      SecurityLayer []string
      Handler       func(req *Request) (APIResponse, error)
  }

  BunGo does NOT support path parameters (no /users/:id). Use query params (req.Params)

### Engines

BunGo ships four engine adapters: HTTP (`engine.NewHTTPEngine()`), HTTPS
(`engine.NewHTTPSEngine(cert, key)`), AWS Lambda (`engine/aws`), and Google Cloud
Functions (`engine/gcp`). Vault3 uses the HTTP engine only; do not add the cloud
engines unless explicitly requested.

The HTTP engine also exposes the public building block Vault3 relies on:

  func (e *HTTPEngine) CreateHandler(srv *bungo.Server) (http.Handler, error)

    Compiles the views and returns the fully wired route mux WITHOUT starting a
    listener, so the application can wrap it (middleware, extra native routes)
    and run http.ListenAndServe itself. Static files under /static/ are served
    from memory-first storage and do NOT pass through security layers.

### Templates and layouts

All .gohtml files live in webDir/layouts/.

  Template: The page-specific file. Always required on a PageRoute.
  Layout:   Optional wrapper. Defines {{block "content" .}}{{end}}.
            The Template fills it with {{define "content"}}...{{end}}.

If a Layout is set (per-route or via SetDefaultLayout), BunGo renders the Template
inside the Layout. Otherwise the Template is rendered standalone.

Handler data is available in templates as Go template fields ({{.PageTitle}}).

Script injection: BunGo automatically injects <script> tags for:
  - window.__BUNGO_DATA__ (the handler's map, JSON-serialized)
  - The compiled JSX bundle (inline by default; external /_bungo/<view>.js when
    asset optimization is enabled)

Injection point: before the first </head> tag; if absent, before </body>. When a
Layout is used, injection happens in the layout file. NEVER manually place BunGo
script tags — the framework handles this.

### React views

View files live in webDir/views/ and are compiled at server start via esbuild.
Supported extensions: .jsx, .tsx, .js, .ts.

BunGo uses the automatic JSX runtime (React 18.2.0 embedded). The compiler injects
two globals that view code can use without importing them:

  _bungoRender(Component, elementId?)
    Mounts the React Component via createRoot. elementId defaults to "root".

  useBungoData()
    Returns window.__BUNGO_DATA__ (the handler map) or {}.

TypeScript views: declarations live in the project root bungo-env.d.ts, included by
tsconfig.json.

Local imports: additional directories like web/components/ are imported from views
with relative paths. Remote URL imports (Deno-style, e.g. https://esm.sh/pkg@ver)
are resolved at build time and normalized to the embedded React.

### Security layers

Security layers are named middleware that run before page or API handlers.

  srv.Security(bungo.SecurityLayer{
      Name: "require_auth",
      Handler: func(req *bungo.Request) bool {
          // ... validate; stash context for later layers/handler:
          req.Internal["UserID"] = id
          return true   // false → HTTP 401 Unauthorized
      },
  })

Attach to routes via SecurityLayer: []string{"require_auth", "load_viewer"}.
Layers execute in the order listed. If any returns false the chain stops and the
response is HTTP 401 Unauthorized (never 403, never a redirect).

req.Internal is a shared mutable map for passing data between layers and the final
handler.

### Page routes

Page routes combine a Go handler, an HTML template, and an optional React view into a
single URL. Template is always required; Layout and View are optional; a nil Handler
renders the template with no data. At request time: security layers run in order →
handler → template render (inside the layout) → automatic script injection.

### API routes

The full HTTP path is /api/{Version}{Path} (a leading slash is added to Path if
missing). The response Body is marshaled to JSON. Path parameters are NOT
supported — use query parameters (req.Params) or the JSON body.

### API-only servers

srv := bungo.NewServer(engineInstance, "") skips directory validation and static
mounting; only Api() routes can be registered.

### Critical rules for AI agents

  - NEVER generate package.json, node_modules, or npm/yarn/pnpm commands.
    BunGo embeds everything. There is no Node.js toolchain.

  - NEVER manually place <script> tags for React bundles or __BUNGO_DATA__.

  - NEVER import database drivers, ORM libraries, or user-specific models into the
    BunGo framework itself. BunGo is infrastructure only; app-level dependencies
    belong in the project's go.mod. The framework source at ../bungo is READ-ONLY
    for this project — the only file that may be written there is suggestion.md.

  - View files MUST call _bungoRender(Component) to mount; they do NOT import
    _bungoRender or useBungoData.

  - Template (.gohtml) is ALWAYS required on a PageRoute. With a Layout, the
    Template must {{define "content"}}...{{end}}.

  - Security layers returning false produce HTTP 401 Unauthorized (not 403).

  - Static files under web/static/ are public and bypass security layers.
    Never put secrets or user-specific files in static/.

  - API paths are automatically prefixed with /api/{Version}. Do not hardcode
    /api/ in the Path field.

  - Do NOT use Express-style or mux-style path parameters (:id, {id}, wildcards).
    BunGo matches exact paths only.

  - When adding third-party frontend libraries, use Deno-style URL imports.
    Do not create a package.json. (Vault3 currently has none — see frontend.md.)

### Vault3 project conventions

These apply on top of the framework rules above when working in this repository:

- Register page/API/security handlers as methods on `*runtime.Runtime`.
- **Never write a `bungo.ApiRoute` / `PageRoute` literal inline.** Routes go through
  the five closures at the top of `cmd/vault3/main.go` — `api` / `page` (authenticated,
  the default), `openAPI` / `anonPage` (public), `viewerPage` (public but
  viewer-aware). Authentication is thereby the default and going public costs a
  visible word in the name, so the whole public surface stays greppable. Full
  table in [backend.md](./backend.md).
- **Vault3 does not call `srv.Serve`.** `cmd/vault3/main.go` builds the handler via
  the engine's public `CreateHandler`, mounts the native `/events` SSE endpoint
  beside it (BunGo responses cannot stream), and wraps everything in
  `rt.WrapHandler` (security headers, cross-origin rejection, socket-IP injection)
  before `http.ListenAndServe`. All through public API — the framework stays unmodified.
- To set or clear session cookies, populate `APIResponse.Cookies` from the API
  handler — never reach into `http.ResponseWriter`.
- A page handler's returned map is serialized verbatim into `window.__BUNGO_DATA__`
  whenever non-empty. Ciphertext payloads (Keyset, ItemRow) are fine there;
  plaintext secrets never are. `view.UserSummary.Auth` is `json:"-"` so its token
  hashes and encrypted TOTP secrets never ship.
- BunGo page handlers cannot redirect server-side (layers yield 401 only); any
  gate that must bounce a browser is client-side by construction.

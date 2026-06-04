# Basic Auth Plugin

![Screen Shot 2020-09-18 at 6 12 41 PM](https://user-images.githubusercontent.com/934364/93649709-9cf96c00-f9da-11ea-8f41-103fe6b61793.png)

Protect a non-public (dev/stage) site behind a shared HTTP Basic Auth credential so it is reachable
only by people who hold the user/password — QA, reviewers, and other stakeholders. dotCMS users and
permissions are intentionally not involved; once a visitor passes the challenge they see the whole
site (pages **and** sub-resources: CSS, JS, images, files) uniformly.

This is the dotCMS-internal equivalent of an nginx `auth_basic` / Apache `mod_auth_basic` edge gate.
If you control the reverse proxy / CDN in front of dotCMS, doing the Basic Auth there is the more
standard approach; use this plugin when you cannot add an edge gate.

## How to build

Requires JDK 11+. Build the bundle JAR with the Maven wrapper:
`./mvnw clean package`

This produces a single OSGi bundle at `target/com.dotcms.basicauth-1.0.0.jar`. (No separate
fragment jar is needed on current dotCMS — the required third-party packages are exported by core.)

* **To install this bundle:**

    Copy the bundle jar files inside the Felix OSGI container (*dotCMS/felix/load*).
        
    OR
        
    Upload the bundle jars files using the dotCMS UI (*CMS Admin->Dynamic Plugins->Upload Plugin*).

* **To uninstall this bundle:**
    
    Remove the bundle jars files from the Felix OSGI container (*dotCMS/felix/load*).

    OR

    Undeploy the bundle jars using the dotCMS UI (*CMS Admin->Dynamic Plugins->Undeploy*).


## How to Use

The plugin registers a `BasicAuthWebInterceptor` that runs at the perimeter (before the rules engine
and the asset servlets) on every request. Configure it with dotCMS `Config` properties (e.g. in
`dotmarketing-config-ext.properties`, in `dotcms-config-cluster` overrides, or as environment
variables prefixed with `DOT_`):

| Property | Required | Default | Description |
|---|---|---|---|
| `BASICAUTH_ENFORCEMENT` | no | `AUTO` | Which mechanism enforces. `AUTO`: the interceptor gates the hosts in `BASICAUTH_HOSTS`, and the legacy actionlet enforces on any other host. `INTERCEPTOR`: interceptor everywhere, actionlet inert. `ACTIONLET`: legacy rule everywhere, interceptor inert. |
| `BASICAUTH_HOSTS` | yes | _(empty → gate disabled)_ | Comma-separated server names to protect, e.g. `dev.example.com,staging.example.com`. Use `*` to protect every host. |
| `BASICAUTH_CREDENTIALS` | yes | _(none)_ | Comma-separated `user:password` pairs, e.g. `qa:s3cret,reviewer:letmein`. Multiple pairs allow per-stakeholder credentials. (A literal comma in a password is not supported.) |
| `BASICAUTH_REALM` | no | `dotCMS` | Realm shown in the browser's Basic Auth prompt. |
| `BASICAUTH_EXCLUDE_URIS` | no | `^/dotAdmin,^/api,^/c/,^/dwr,^/dotcms,^/dotmgt,^/webdav,^/html/portlet` | Comma-separated case-insensitive regexes (matched as "contains", anchor with `^`) that are **never** gated, so the dotCMS back-end, REST API and health checks stay reachable. Override only if you know what you are doing. |
| `BASICAUTH_STRIP_ONLY_BASIC_HEADERS` | no | `true` | When `true`, only `Basic`-scheme credentials are hidden from downstream on success; `Bearer`/JWT and other schemes pass through untouched. Set `false` to hide every `Authorization` header. |

Example:

```properties
BASICAUTH_HOSTS=dev.example.com,staging.example.com
BASICAUTH_CREDENTIALS=qa:s3cret,reviewer:letmein
BASICAUTH_REALM=Staging
```

On a protected host the interceptor challenges any request without a valid shared credential
(`401` + `WWW-Authenticate: Basic`). When a valid credential is presented it lets the request
through with the `Authorization` header **stripped**, so neither the rules engine nor the asset
servlets (`SpeedyAssetServlet`, `BinaryExporterServlet`, `ShortyServlet`) try to interpret the
shared credential as a dotCMS user login. This is what gives uniform behavior across pages and
sub-resources and avoids the asset `401` described in dotCMS/core#35536.

No rule configuration is required for the interceptor.

## Legacy: the Basic Auth rules-engine actionlet

Earlier versions configured Basic Auth through a Rules Engine **actionlet** (Rule Engine portlet →
add a rule → "Basic Auth" action → `username:password`). This path is still **supported for backward
compatibility** — existing rules keep working — but it is not recommended for new setups because a
rule only fires during page rendering and therefore cannot gate asset sub-resources: browsers replay
the `Authorization` header on every CSS/JS/image request and those hit the asset servlets directly,
which on current dotCMS reject the unknown credential with an empty `401` (dotCMS/core#29869 /
\#35536). The actionlet does **not** strip the header, so this asset `401` persists unless the
core-side fix is deployed. Use the interceptor for full page + sub-resource coverage.

### Choosing between the two (`BASICAUTH_ENFORCEMENT`)

Both ship in the plugin; exactly one enforces a given request:

- **`AUTO`** (default): the interceptor gates the hosts in `BASICAUTH_HOSTS`; the actionlet enforces
  on any host the interceptor is **not** gating. Upgrading an existing install changes nothing until
  you set `BASICAUTH_HOSTS` — your rules keep enforcing. To migrate, set `BASICAUTH_HOSTS`/
  `BASICAUTH_CREDENTIALS` for those hosts (the interceptor takes over and the rule auto-yields), then
  delete the rule.
- **`INTERCEPTOR`**: the interceptor enforces everywhere; the actionlet never challenges (existing
  rules become inert).
- **`ACTIONLET`**: the legacy rule enforces everywhere; the interceptor never runs even if
  `BASICAUTH_HOSTS` is set.


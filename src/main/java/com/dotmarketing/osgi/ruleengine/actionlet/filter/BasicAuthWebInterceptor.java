package com.dotmarketing.osgi.ruleengine.actionlet.filter;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.RegEX;
import com.dotmarketing.util.UtilMethods;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Perimeter HTTP Basic Auth gate for non-public (dev/stage) sites.
 *
 * <p>This interceptor is the single owner of the {@code Authorization: Basic} header for the
 * protected hosts. It runs at the {@code InterceptorFilter} stage — before {@code CMSFilter}
 * (where {@code EVERY_REQUEST} rules fire) and before the asset servlets
 * ({@code SpeedyAssetServlet}, {@code BinaryExporterServlet}, {@code ShortyServlet}). Because it
 * sees every request (pages <em>and</em> sub-resources) uniformly, it avoids the EVERY_PAGE /
 * EVERY_REQUEST split that made the old rules-engine actionlet unable to gate assets.</p>
 *
 * <p>For each request to a protected host (and not on an excluded path):</p>
 * <ul>
 *   <li>If a configured {@code user:password} is presented via {@code Authorization: Basic}, the
 *       request continues with the header <strong>stripped</strong> (see
 *       {@link AuthorizationStrippingRequestWrapper}) so neither the rules engine nor the asset
 *       servlets re-interpret it as a dotCMS user login (the root cause of dotCMS/core#35536).</li>
 *   <li>Otherwise a {@code 401} challenge with {@code WWW-Authenticate: Basic} is returned and the
 *       filter chain is stopped.</li>
 * </ul>
 *
 * <p>This is the dotCMS-internal equivalent of an nginx {@code auth_basic} / Apache
 * {@code mod_auth_basic} edge gate. dotCMS users and permissions are intentionally not involved.</p>
 *
 * <h3>Configuration ({@link Config} properties)</h3>
 * <pre>
 *   BASICAUTH_HOSTS=dev.example.com,staging.example.com   # server names to protect; "*" = all; empty = disabled
 *   BASICAUTH_CREDENTIALS=qa:s3cret,stakeholder:letmein    # comma-separated user:password pairs
 *   BASICAUTH_REALM=dotCMS                                 # challenge realm (optional)
 *   BASICAUTH_EXCLUDE_URIS=^/dotAdmin,^/api,...            # regex (contains, case-insensitive) never gated
 *   BASICAUTH_STRIP_ONLY_BASIC_HEADERS=true                # keep Bearer/JWT intact on protected hosts
 * </pre>
 */
public class BasicAuthWebInterceptor implements WebInterceptor {

    static final String HOSTS_KEY = "BASICAUTH_HOSTS";
    static final String CREDENTIALS_KEY = "BASICAUTH_CREDENTIALS";
    static final String REALM_KEY = "BASICAUTH_REALM";
    static final String EXCLUDE_URIS_KEY = "BASICAUTH_EXCLUDE_URIS";

    /**
     * Selects which mechanism enforces Basic Auth so the interceptor and the legacy
     * {@link com.dotmarketing.osgi.ruleengine.actionlet.BasicAuthActionlet} never both challenge the
     * same request. {@code AUTO} (default): the interceptor gates the hosts in {@link #HOSTS_KEY} and
     * the actionlet enforces on any other host. {@code INTERCEPTOR}: interceptor everywhere, actionlet
     * inert. {@code ACTIONLET}: legacy rule everywhere, interceptor inert.
     */
    public static final String ENFORCEMENT_KEY = "BASICAUTH_ENFORCEMENT";
    static final String MODE_AUTO = "AUTO";
    static final String MODE_INTERCEPTOR = "INTERCEPTOR";
    static final String MODE_ACTIONLET = "ACTIONLET";

    /**
     * When {@code true} (default), only {@code Basic}-scheme {@code Authorization} headers are
     * stripped on success; other schemes (Bearer/JWT/etc.) are preserved so token-authenticated
     * requests still work. Set {@code false} to strip every {@code Authorization} header.
     */
    static final String STRIP_ONLY_BASIC_KEY = "BASICAUTH_STRIP_ONLY_BASIC_HEADERS";

    private static final String ALL_HOSTS = "*";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String DEFAULT_REALM = "dotCMS";

    /**
     * Infrastructure paths that must never be gated, otherwise the gate would lock out the dotCMS
     * back-end UI, REST API, health checks, etc. Overridable via {@link #EXCLUDE_URIS_KEY}.
     * Matched with {@link RegEX#containsCaseInsensitive(String, String)} ({@code ^} anchors start).
     */
    private static final String DEFAULT_EXCLUDE_URIS = String.join(",",
            "^/dotAdmin", "^/api", "^/c/", "^/dwr", "^/dotcms", "^/dotmgt", "^/webdav", "^/html/portlet");

    @Override
    public String[] getFilters() {
        // null => evaluate on every request (pages + sub-resources); host/path scoping is applied
        // inside intercept() so the gate is uniform across the whole protected site.
        return null;
    }

    @Override
    public boolean isActive() {
        // Inert when enforcement is forced to the legacy actionlet; otherwise active once hosts are set.
        return !MODE_ACTIONLET.equals(enforcementMode())
                && UtilMethods.isSet(Config.getStringProperty(HOSTS_KEY, null));
    }

    /**
     * @return the configured enforcement mode, upper-cased and trimmed; {@link #MODE_AUTO} when unset.
     */
    static String enforcementMode() {
        final String mode = Config.getStringProperty(ENFORCEMENT_KEY, MODE_AUTO);
        return UtilMethods.isSet(mode) ? mode.trim().toUpperCase() : MODE_AUTO;
    }

    /**
     * Decides whether the legacy {@link com.dotmarketing.osgi.ruleengine.actionlet.BasicAuthActionlet}
     * should enforce for the given request, so the two mechanisms never both challenge it.
     *
     * @return {@code true} in {@code ACTIONLET} mode; {@code false} in {@code INTERCEPTOR} mode; in
     * {@code AUTO} mode, {@code true} only when the interceptor is not gating this request's host.
     */
    public static boolean actionletShouldEnforce(final HttpServletRequest request) {
        final String mode = enforcementMode();
        if (MODE_ACTIONLET.equals(mode)) {
            return true;
        }
        if (MODE_INTERCEPTOR.equals(mode)) {
            return false;
        }
        return request == null || !isHostProtected(request.getServerName());
    }

    @Override
    public Result intercept(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {

        if (!isHostProtected(request.getServerName()) || isExcluded(request.getRequestURI())) {
            return Result.NEXT;
        }

        final String authorization = request.getHeader("Authorization");
        if (isAuthorized(authorization)) {
            // Valid shared credential: hide the header from everything downstream so the rules
            // engine and asset servlets never try to authenticate it as a dotCMS user.
            final boolean basicOnly = Config.getBooleanProperty(STRIP_ONLY_BASIC_KEY, true);
            return new Result.Builder()
                    .next()
                    .wrap(new AuthorizationStrippingRequestWrapper(request, basicOnly))
                    .build();
        }

        // No / wrong credential: challenge and stop the chain (asset servlet & rules do not run).
        challenge(response);
        return Result.SKIP_NO_CHAIN;
    }

    private static boolean isHostProtected(final String serverName) {
        final String hosts = Config.getStringProperty(HOSTS_KEY, null);
        if (!UtilMethods.isSet(hosts) || !UtilMethods.isSet(serverName)) {
            return false;
        }
        for (final String host : hosts.split(",")) {
            final String trimmed = host.trim();
            if (ALL_HOSTS.equals(trimmed) || trimmed.equalsIgnoreCase(serverName.trim())) {
                return true;
            }
        }
        return false;
    }

    private boolean isExcluded(final String uri) {
        if (!UtilMethods.isSet(uri)) {
            return false;
        }
        final String excludes = Config.getStringProperty(EXCLUDE_URIS_KEY, DEFAULT_EXCLUDE_URIS);
        for (final String pattern : excludes.split(",")) {
            final String trimmed = pattern.trim();
            if (!trimmed.isEmpty() && RegEX.containsCaseInsensitive(uri, trimmed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return {@code true} when the {@code Authorization} header carries a {@code Basic} credential
     * that matches one of the configured {@code user:password} pairs (constant-time comparison).
     */
    private boolean isAuthorized(final String authorization) {
        if (!UtilMethods.isSet(authorization) || !authorization.startsWith(BASIC_PREFIX)) {
            return false;
        }
        final String presented = authorization.substring(BASIC_PREFIX.length()).trim();
        boolean matched = false;
        // Iterate over all credentials (no early return) to keep the comparison time independent
        // of which credential matched.
        for (final String token : configuredTokens()) {
            if (constantTimeEquals(token, presented)) {
                matched = true;
            }
        }
        return matched;
    }

    /**
     * @return the configured {@code user:password} pairs Base64-encoded to match the value carried
     * after {@code "Basic "} in the {@code Authorization} header.
     */
    private Set<String> configuredTokens() {
        final String credentials = Config.getStringProperty(CREDENTIALS_KEY, null);
        if (!UtilMethods.isSet(credentials)) {
            return Collections.emptySet();
        }
        final Set<String> tokens = new LinkedHashSet<>();
        for (final String pair : credentials.split(",")) {
            final String trimmed = pair.trim();
            if (trimmed.indexOf(':') > 0) {
                tokens.add(Base64.getEncoder()
                        .encodeToString(trimmed.getBytes(StandardCharsets.UTF_8)));
            }
        }
        return tokens;
    }

    private void challenge(final HttpServletResponse response) throws IOException {
        final String realm = Config.getStringProperty(REALM_KEY, DEFAULT_REALM);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write("401 Unauthorized");
        response.flushBuffer();
    }

    private static boolean constantTimeEquals(final String a, final String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}

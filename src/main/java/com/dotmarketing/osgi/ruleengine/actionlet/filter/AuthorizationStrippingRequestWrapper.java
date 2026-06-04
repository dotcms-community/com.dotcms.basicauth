package com.dotmarketing.osgi.ruleengine.actionlet.filter;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Request wrapper that hides the {@code Authorization} header (case-insensitive) from all header
 * accessors, so downstream servlets behave as if no credentials were sent.
 * <p>
 * When {@code basicOnly} is {@code true} (the default behavior), only {@code Basic}-scheme values
 * are hidden; other schemes ({@code Bearer}, JWT, {@code Negotiate}, etc.) are left untouched so a
 * legitimate token-authenticated asset request is not broken. When {@code basicOnly} is
 * {@code false}, every {@code Authorization} value is hidden regardless of scheme.
 */
public class AuthorizationStrippingRequestWrapper extends HttpServletRequestWrapper {

    private static final String AUTHORIZATION = "authorization";
    private static final String BASIC_PREFIX = "basic ";

    private final boolean basicOnly;

    public AuthorizationStrippingRequestWrapper(final HttpServletRequest request, final boolean basicOnly) {
        super(request);
        this.basicOnly = basicOnly;
    }

    /**
     * @return {@code true} if the given {@code Authorization} value should be hidden from downstream.
     */
    private boolean shouldStrip(final String value) {
        if (value == null) {
            return false;
        }
        return !this.basicOnly || value.toLowerCase().startsWith(BASIC_PREFIX);
    }

    @Override
    public String getHeader(final String name) {
        final String value = super.getHeader(name);
        if (AUTHORIZATION.equalsIgnoreCase(name) && shouldStrip(value)) {
            return null;
        }
        return value;
    }

    @Override
    public Enumeration<String> getHeaders(final String name) {
        if (!AUTHORIZATION.equalsIgnoreCase(name)) {
            return super.getHeaders(name);
        }
        final List<String> kept = Collections.list(super.getHeaders(name)).stream()
                .filter(value -> !shouldStrip(value))
                .collect(Collectors.toList());
        return Collections.enumeration(kept);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        // Only hide the Authorization name when no values survive stripping; otherwise a surviving
        // non-Basic credential (e.g. Bearer) would be unreachable by name.
        final boolean authStillPresent = Collections.list(super.getHeaders(AUTHORIZATION)).stream()
                .anyMatch(value -> !shouldStrip(value));
        final List<String> names = Collections.list(super.getHeaderNames()).stream()
                .filter(name -> authStillPresent || !AUTHORIZATION.equalsIgnoreCase(name))
                .collect(Collectors.toList());
        return Collections.enumeration(names);
    }
}

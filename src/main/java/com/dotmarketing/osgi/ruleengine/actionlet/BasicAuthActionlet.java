package com.dotmarketing.osgi.ruleengine.actionlet;

import static com.google.common.base.Preconditions.checkState;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import com.google.common.base.Preconditions;
import com.dotmarketing.portlets.rules.RuleComponentInstance;
import com.dotmarketing.portlets.rules.actionlet.RuleActionlet;
import com.dotmarketing.portlets.rules.model.ParameterModel;
import com.dotmarketing.portlets.rules.parameter.ParameterDefinition;
import com.dotmarketing.portlets.rules.parameter.display.TextInput;
import com.dotmarketing.portlets.rules.parameter.type.TextType;
import com.dotmarketing.osgi.ruleengine.actionlet.filter.BasicAuthWebInterceptor;
import com.dotmarketing.util.Logger;
import io.vavr.control.Try;


/**
 * Rules-engine actionlet that challenges page requests with HTTP Basic Auth using a configured
 * {@code username:password}. This is the original (pre-1.0) enforcement path, retained for backward
 * compatibility so existing rules keep working.
 *
 * <p>For full coverage — including asset sub-resources (CSS/JS/images), which a rule cannot gate —
 * prefer the {@link com.dotmarketing.osgi.ruleengine.actionlet.filter.BasicAuthWebInterceptor}
 * (configured via {@code BASICAUTH_HOSTS} / {@code BASICAUTH_CREDENTIALS}). The
 * {@code BASICAUTH_ENFORCEMENT} property selects which mechanism enforces; in the default
 * {@code AUTO} mode this actionlet enforces only on hosts the interceptor is not gating.</p>
 */
public class BasicAuthActionlet extends RuleActionlet<BasicAuthActionlet.Instance> {


    private static final long serialVersionUID = 1L;

    public static final String INPUT_BASICAUTH_KEY = "basicauth";
    private static final String I18N_BASE = "api.system.ruleengine.actionlet.BasicAuth";

    public BasicAuthActionlet() {
        super(I18N_BASE, new ParameterDefinition<>(1, INPUT_BASICAUTH_KEY,
                        new TextInput<>(new TextType().minLength(1))));
    }


    @Override
    public Instance instanceFrom(Map<String, ParameterModel> parameters) {
        return new Instance(parameters);
    }


    /**
     * Challenges the request with Basic Auth unless it carries the configured credential. Yields
     * (no-op) when the {@link BasicAuthWebInterceptor} is the active gate for this request — see
     * {@link BasicAuthWebInterceptor#actionletShouldEnforce(HttpServletRequest)} — so the two
     * mechanisms never both challenge the same request.
     *
     * @return {@code true} when the action completed (credential valid, challenge issued, or yielded);
     * {@code false} only if an unexpected error occurred.
     */
    @Override
    public boolean evaluate(HttpServletRequest request, HttpServletResponse response, Instance instance) {
        if (!BasicAuthWebInterceptor.actionletShouldEnforce(request)) {
            // The BasicAuthWebInterceptor owns the gate for this request (per BASICAUTH_ENFORCEMENT);
            // do not double-challenge.
            Logger.debug(BasicAuthActionlet.class,
                    "BasicAuthActionlet yielding to BasicAuthWebInterceptor for this request.");
            return true;
        }

        boolean success = false;
        try {
            final String auth = Try.of(() -> request.getHeader("Authorization")
                    .replace("Basic ", "").trim()).getOrNull();
            if (auth != null && instance.basicAuth.equals(auth)) {
                return true;
            }

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "Basic");
            response.getWriter().write("401");
            response.getWriter().close();
            return true;
        } catch (Exception e) {
            Logger.error(BasicAuthActionlet.class, "Error executing BasicAuthActionlet.", e);
        }
        return success;
    }


    
    
    

    public class Instance implements RuleComponentInstance {

        String getBasicAuth() {
            return this.basicAuth;
        }
        private final String basicAuth;

        public Instance(Map<String, ParameterModel> parameters) {
            checkState(parameters != null && parameters.size() == 1, "Basic Auth requires parameter '%s'.",
                            INPUT_BASICAUTH_KEY);
            assert parameters != null;
            this.basicAuth = Try.of(()->  Base64.encodeBase64String(parameters.get(INPUT_BASICAUTH_KEY).getValue().getBytes())).getOrNull();
            Preconditions.checkArgument(StringUtils.isNotBlank(this.basicAuth),
                            "BasicAuth requires a user:passwd");

        }
    }
}

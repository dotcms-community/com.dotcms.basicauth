package com.dotmarketing.osgi.ruleengine.actionlet;

import org.osgi.framework.BundleContext;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotmarketing.filters.InterceptorFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.osgi.ruleengine.actionlet.filter.BasicAuthWebInterceptor;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import io.vavr.control.Try;

/**
 * This Activator class registers and unregisters the {@link BasicAuthWebInterceptor} perimeter gate
 * (the supported way to protect a non-public site with a shared credential), plus the deprecated
 * {@link BasicAuthActionlet} which is kept for backward compatibility only and no longer enforces.
 *
 * @author Oswaldo Gallango
 * @version 1.0
 * @since 10/17/2016
 */
public class Activator extends GenericBundleActivator {

    private String interceptorName;

    @Override
    public void start ( BundleContext bundleContext ) throws Exception {

        //Initializing services...
        initializeServices( bundleContext );

        //Register the deprecated Actionlet (kept for backward compatibility; no longer enforces)
        registerRuleActionlet( bundleContext, new BasicAuthActionlet() );

        //Register the perimeter Basic Auth gate interceptor (runs first, on every request)
        final BasicAuthWebInterceptor interceptor = new BasicAuthWebInterceptor();
        this.interceptorName = interceptor.getName();
        final WebInterceptorDelegate delegate = getInterceptorDelegate();
        Try.run( () -> delegate.remove( this.interceptorName, true ) )
                .onFailure( e -> Logger.warn( this, "Unable to remove existing interceptor: " + e.getMessage() ) );
        delegate.addFirst( interceptor );
        Logger.info( this, "Registered BasicAuthWebInterceptor" );
    }

    @Override
    public void stop ( BundleContext bundleContext ) throws Exception {

        //Remove the Authorization-header strip interceptor
        if ( this.interceptorName != null ) {
            Try.run( () -> getInterceptorDelegate().remove( this.interceptorName, true ) )
                    .onFailure( e -> Logger.warn( this, "Unable to remove interceptor: " + e.getMessage() ) );
        }

        //Unregister the Actionlet
        unregisterServices( bundleContext );
    }

    private WebInterceptorDelegate getInterceptorDelegate () {
        return FilterWebInterceptorProvider.getInstance( Config.CONTEXT )
                .getDelegate( InterceptorFilter.class );
    }

}

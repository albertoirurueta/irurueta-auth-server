/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.irurueta.authserver.authorization.api.web.x509;

import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

// tag::x509-login-method-fragment[]
/**
 * Contributes the sign-in with a client certificate to the login page: a form with one button that posts, with the
 * CSRF token, to {@code POST /login/x509}. The template reads {@link #action()} through this bean, because where the
 * form posts depends on the transport:
 * <ul>
 *     <li>with a proxy that forwards the certificate, the proxy fronts the whole application, so the form posts to the
 *     relative path, on the origin of the page;</li>
 *     <li>with only the dedicated TLS port, the certificate is requested by that port alone, so a page served on any
 *     other port posts to the same host on that port over {@code https}; a page already served on that port posts to
 *     the relative path.</li>
 * </ul>
 * The session cookie and the CSRF token stay valid on the other port (cookies belong to a host, not to a port), but a
 * browser only sends a cookie with a {@code SameSite} restriction on a post between pages of the same site, and it
 * counts {@code http} and {@code https} as different sites: the main port must be served over {@code https} too, or
 * the login page must be opened on the TLS port. The bean only exists while the sign-in with a certificate is enabled.
 */
public class X509LoginMethodFragment implements LoginMethodFragment {

    /** Position of the certificate sign-in in the login page: after the social one, before the one-time tokens. */
    public static final int ORDER = 260;

    /** Scheme of the dedicated TLS port. */
    private static final String HTTPS = "https";

    /** Settings, which tell the transports and the TLS port. */
    private final X509Properties properties;

    /**
     * Creates the fragment.
     *
     * @param properties settings of the sign-in with a certificate.
     */
    public X509LoginMethodFragment(final X509Properties properties) {
        this.properties = properties;
    }

    /**
     * Gets the template that holds the fragment.
     *
     * @return {@code login-x509}.
     */
    @Override
    public String templateName() {
        return "login-x509";
    }

    /**
     * Gets the fragment of the template.
     *
     * @return {@code login}.
     */
    @Override
    public String fragmentName() {
        return "login";
    }

    /**
     * Gets the position of the fragment.
     *
     * @return {@link #ORDER}.
     */
    @Override
    public int order() {
        return ORDER;
    }

    /**
     * Gets the address the form of the page being rendered posts to.
     *
     * @return the address of the sign-in request for the current request; the relative path when there is none.
     */
    public String action() {
        if (RequestContextHolder.getRequestAttributes() instanceof final ServletRequestAttributes attributes) {
            return action(attributes.getRequest());
        }
        return X509ChainCustomizer.LOGIN_PATH;
    }

    /**
     * Gets the address the form of a page posts to.
     *
     * @param request the request of the page.
     * @return the relative path (with the context path) when a proxy forwards the certificate, when there is no TLS
     *         port or when the page is served on it; otherwise the absolute address on the TLS port of the same host.
     */
    public String action(final HttpServletRequest request) {
        final var path = request.getContextPath() + X509ChainCustomizer.LOGIN_PATH;
        if (properties.forwardedEnabled() || !properties.tlsEnabled()
                || request.getLocalPort() == properties.port()) {
            return path;
        }
        return UriComponentsBuilder.newInstance().scheme(HTTPS).host(request.getServerName())
                .port(properties.port()).path(path).toUriString();
    }
}
// end::x509-login-method-fragment[]

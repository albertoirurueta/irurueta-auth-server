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
package com.irurueta.authserver.authorization.api.web.login;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.stereotype.Component;

// tag::login-headers[]
/**
 * Adds the security headers of the server-rendered pages: a content security policy that only allows same-origin
 * resources and forbids framing, {@code X-Content-Type-Options} and {@code Referrer-Policy}.
 *
 * <p>The policy deliberately has no {@code form-action} directive: browsers also apply it to the redirects that follow
 * a form submission, so {@code form-action 'self'} would block the redirect from the login or consent form back to the
 * client application's {@code redirect_uri}, which is on another origin.
 */
@Component
@Order(0)
public class LoginHeadersCustomizer implements LoginChainCustomizer {

    /** Content security policy of the pages: same-origin resources only (no inline scripts or styles), no framing. */
    public static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; frame-ancestors 'none'";

    @Override
    public void customize(final HttpSecurity http) {
        http.headers(headers -> {
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY));
            headers.contentTypeOptions(Customizer.withDefaults());
            headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER));
        });
    }
}
// end::login-headers[]

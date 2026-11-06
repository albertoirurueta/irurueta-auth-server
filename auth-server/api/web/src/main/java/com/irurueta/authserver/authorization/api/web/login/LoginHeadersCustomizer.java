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

import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.stereotype.Component;

// tag::login-headers[]
/**
 * Adds the security headers of the server-rendered pages: the content security policy that
 * {@link LoginContentSecurityPolicy} builds (same-origin resources only, no framing, and the origin of an absolute
 * branding logo URL for images), {@code X-Content-Type-Options} and {@code Referrer-Policy}.
 *
 * <p>The policy deliberately has no {@code form-action} directive: browsers also apply it to the redirects that follow
 * a form submission, so {@code form-action 'self'} would block the redirect from the login or consent form back to the
 * client application's {@code redirect_uri}, which is on another origin.
 */
@Component
@Order(0)
@RequiredArgsConstructor
public class LoginHeadersCustomizer implements LoginChainCustomizer {

    /** Builds the content security policy from the branding. */
    private final LoginContentSecurityPolicy contentSecurityPolicy;

    @Override
    public void customize(final HttpSecurity http) {
        final var policy = contentSecurityPolicy.policy();
        http.headers(headers -> {
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(policy));
            headers.contentTypeOptions(Customizer.withDefaults());
            headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER));
        });
    }
}
// end::login-headers[]

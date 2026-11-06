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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * Unit tests of {@link LoginHeadersCustomizer}.
 */
class LoginHeadersCustomizerTest {

    /**
     * Verifies that the policy forbids framing and restricts resources to the same origin, and has no form-action.
     */
    @Test
    void contentSecurityPolicy_whenRead_restrictsResourcesAndFrames() {
        assertEquals("default-src 'self'; frame-ancestors 'none'",
                LoginHeadersCustomizer.CONTENT_SECURITY_POLICY);
    }

    /**
     * Verifies that the policy, content type options and referrer policy are configured.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_configuresPolicyContentTypeOptionsAndReferrerPolicy() {
        final var http = mock(HttpSecurity.class);
        final var headers = mock(HeadersConfigurer.class);
        final var csp = mock(HeadersConfigurer.ContentSecurityPolicyConfig.class);
        final var referrer = mock(HeadersConfigurer.ReferrerPolicyConfig.class);
        final var headersCaptor = ArgumentCaptor.<Customizer<HeadersConfigurer<HttpSecurity>>>captor();
        when(http.headers(headersCaptor.capture())).thenReturn(http);

        new LoginHeadersCustomizer().customize(http);
        headersCaptor.getValue().customize(headers);

        final var cspCaptor = ArgumentCaptor
                .<Customizer<HeadersConfigurer.ContentSecurityPolicyConfig>>captor();
        verify(headers).contentSecurityPolicy(cspCaptor.capture());
        cspCaptor.getValue().customize(csp);
        verify(csp).policyDirectives(LoginHeadersCustomizer.CONTENT_SECURITY_POLICY);

        verify(headers).contentTypeOptions(any());

        final var referrerCaptor = ArgumentCaptor
                .<Customizer<HeadersConfigurer.ReferrerPolicyConfig>>captor();
        verify(headers).referrerPolicy(referrerCaptor.capture());
        referrerCaptor.getValue().customize(referrer);
        verify(referrer).policy(ReferrerPolicy.NO_REFERRER);
    }
}

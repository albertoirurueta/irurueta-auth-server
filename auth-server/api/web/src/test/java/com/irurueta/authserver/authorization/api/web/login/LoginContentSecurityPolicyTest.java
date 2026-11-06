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

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

/**
 * Unit tests of {@link LoginContentSecurityPolicy}.
 */
class LoginContentSecurityPolicyTest {

    /**
     * Verifies the policy used when the logo, if any, is served by this application.
     */
    @Test
    void defaultPolicy_whenRead_restrictsResourcesAndFramesWithoutFormAction() {
        assertEquals("default-src 'self'; frame-ancestors 'none'; img-src 'self' data:",
                LoginContentSecurityPolicy.DEFAULT_POLICY);
    }

    /**
     * Verifies that without branding properties (a web slice that does not enable them) the default policy applies.
     */
    @Test
    void policy_whenBrandingIsNotConfigured_isTheDefaultPolicy() {
        final var policy = new LoginContentSecurityPolicy(new StaticListableBeanFactory()
                .getBeanProvider(BrandingProperties.class));

        assertEquals(LoginContentSecurityPolicy.DEFAULT_POLICY, policy.policy());
    }

    /**
     * Verifies that a logo that is not an absolute {@code http(s)} URL adds no image source.
     *
     * @param logoUrl the configured logo URL.
     */
    @ParameterizedTest
    @ValueSource(strings = {"", "/images/logo.png", "images/logo.png", "data:image/png;base64,AAAA",
        "ftp://files.example.com/logo.png", "https:///logo.png", "https://bad host/logo.png", "//cdn.example.com/logo"})
    void policy_whenLogoIsNotAnAbsoluteWebUrl_isTheDefaultPolicy(final String logoUrl) {
        assertEquals(LoginContentSecurityPolicy.DEFAULT_POLICY, policyFor(logoUrl));
    }

    /**
     * Verifies that an absolute {@code http(s)} logo URL adds its origin, and only its origin, as an image source.
     *
     * @param logoUrl the configured logo URL.
     * @param origin  the origin expected in the policy.
     */
    @ParameterizedTest
    @CsvSource({
        "https://cdn.example.com/brand/logo.png?v=2, https://cdn.example.com",
        "HTTP://CDN.Example.com:8080/logo.png, http://cdn.example.com:8080",
        "https://cdn.example.com, https://cdn.example.com"})
    void policy_whenLogoIsAnAbsoluteWebUrl_allowsItsOriginForImages(final String logoUrl, final String origin) {
        assertEquals("default-src 'self'; frame-ancestors 'none'; img-src 'self' data: " + origin,
                policyFor(logoUrl));
    }

    /**
     * Builds the policy for a configured logo URL.
     *
     * @param logoUrl the logo URL.
     * @return the policy.
     */
    private static String policyFor(final String logoUrl) {
        final var branding = new BrandingProperties(null, logoUrl, null);
        return new LoginContentSecurityPolicy(new StaticListableBeanFactory(Map.of("branding", branding))
                .getBeanProvider(BrandingProperties.class)).policy();
    }
}

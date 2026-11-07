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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * Unit tests of {@link DeviceClientAuthenticationConverter}.
 */
class DeviceClientAuthenticationConverterTest {

    /** Path of the device authorization endpoint. */
    private static final String DEVICE_AUTHORIZATION = "/oauth2/device_authorization";

    /** Path of the token endpoint. */
    private static final String TOKEN = "/oauth2/token";

    /** Identifier of the client. */
    private static final String CLIENT_ID = "device-client";

    /** Converter under test. */
    private final DeviceClientAuthenticationConverter converter =
            new DeviceClientAuthenticationConverter(DEVICE_AUTHORIZATION);

    /**
     * Verifies that the request for the codes authenticates the client named in it.
     */
    @Test
    void convert_whenTheDeviceAsksForItsCodes_returnsTheClient() {
        final var request = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        request.setParameter("client_id", CLIENT_ID);

        final var token = assertInstanceOf(DeviceClientAuthenticationToken.class, converter.convert(request));

        assertEquals(CLIENT_ID, token.getPrincipal());
    }

    /**
     * Verifies that the poll with the device code grant authenticates the client named in it.
     */
    @Test
    void convert_whenTheDevicePolls_returnsTheClient() {
        final var request = tokenRequest("urn:ietf:params:oauth:grant-type:device_code");
        request.setParameter("device_code", "code");

        assertInstanceOf(DeviceClientAuthenticationToken.class, converter.convert(request));
    }

    /**
     * Verifies that a request that is not the device flow's is left to the other converters, even if it names a client
     * as a PKCE request does.
     */
    @Test
    void convert_whenTheRequestIsNotTheDeviceFlows_returnsNull() {
        final var pkce = tokenRequest("authorization_code");
        pkce.setParameter("code_verifier", "verifier");
        final var noClient = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        final var noDeviceCode = tokenRequest("urn:ietf:params:oauth:grant-type:device_code");
        final var wrongMethod = new MockHttpServletRequest("GET", DEVICE_AUTHORIZATION);
        wrongMethod.setParameter("client_id", CLIENT_ID);

        assertNull(converter.convert(pkce));
        assertNull(converter.convert(noClient));
        assertNull(converter.convert(noDeviceCode));
        assertNull(converter.convert(wrongMethod));
    }

    /**
     * Verifies that a request that carries the credential of a confidential client is left to the converters of that
     * credential.
     */
    @Test
    void convert_whenTheRequestCarriesACredential_returnsNull() {
        final var basic = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        basic.setParameter("client_id", CLIENT_ID);
        basic.addHeader("Authorization", "Basic abc");
        final var secret = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        secret.setParameter("client_id", CLIENT_ID);
        secret.setParameter("client_secret", "secret");
        final var assertion = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        assertion.setParameter("client_id", CLIENT_ID);
        assertion.setParameter("client_assertion", "jwt");

        assertNull(converter.convert(basic));
        assertNull(converter.convert(secret));
        assertNull(converter.convert(assertion));
    }

    /**
     * Verifies that a client named twice, or not at all, is an invalid request.
     */
    @Test
    void convert_whenTheClientIsNamedTwiceOrBlank_throwsInvalidRequest() {
        final var twice = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        twice.addParameter("client_id", CLIENT_ID);
        twice.addParameter("client_id", "other");
        final var blank = new MockHttpServletRequest("POST", DEVICE_AUTHORIZATION);
        blank.setParameter("client_id", " ");

        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(twice));
        assertThrows(OAuth2AuthenticationException.class, () -> converter.convert(blank));
    }

    /**
     * Builds a request to the token endpoint.
     *
     * @param grantType the grant type.
     * @return the request, which names the client.
     */
    private static MockHttpServletRequest tokenRequest(final String grantType) {
        final var request = new MockHttpServletRequest("POST", TOKEN);
        request.setParameter("client_id", CLIENT_ID);
        request.setParameter("grant_type", grantType);
        return request;
    }
}

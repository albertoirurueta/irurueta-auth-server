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
package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a remembered device skips the second factor on the next sign-in and stops doing so once revoked.
 */
class TrustedDeviceIT extends AbstractMfaFlow {

    /** Path of the second-factor page. */
    private static final String SECOND_FACTOR_PAGE = "/login/second-factor";

    /** Port that stores the trusted devices. */
    @Autowired
    private TrustedDeviceRepository trustedDevices;

    /**
     * Verifies that the device is remembered by the cookie, skips the second factor (tokens still say multi-factor),
     * and is asked for the code again after it is revoked.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenDeviceIsTrusted_isSkippedUntilTheDeviceIsRevoked() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();

        final var first = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), first);
        final var remembered = postSecondFactor(first, getTools().codeNow(enrolled.id(), 0), false, true);
        final var cookie = remembered.getResponse().getCookie(TRUSTED_DEVICE_COOKIE);
        assertNotNull(cookie, "The device cookie must be written");
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.getSecure());
        assertEquals(1, trustedDevices.findByUser(enrolled.id(), Instant.now()).size());

        final var second = new MockHttpSession();
        final var verifier = newVerifier();
        final var secondUri = signInForAuthorization(enrolled.user(), client, verifier, Map.of(), second);
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(second).cookie(cookie))
                .andExpect(status().is3xxRedirection());
        final var tokens = completeAuthorization(secondUri, client, verifier, second);
        assertEquals("urn:irurueta:acr:mfa",
                AuthServerFixtures.claimsOf(tokens.get("access_token").asString()).get("acr").asString());

        final var device = trustedDevices.findByUser(enrolled.id(), Instant.now()).getFirst();
        assertTrue(trustedDevices.revoke(enrolled.id(), device.id()));

        final var third = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), third);
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(third).cookie(cookie)).andExpect(status().isOk());
    }
}

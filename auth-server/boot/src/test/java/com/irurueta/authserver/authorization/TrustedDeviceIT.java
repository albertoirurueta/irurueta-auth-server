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

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.PasswordFactor;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a remembered device skips the second factor on the next sign-in (without the tokens claiming a second
 * factor), never satisfies a step-up request, and stops skipping it once revoked.
 */
class TrustedDeviceIT extends AbstractMfaFlow {

    /** Port that stores the trusted devices. */
    @Autowired
    private TrustedDeviceRepository trustedDevices;

    // tag::mfa-trusted-device-it[]
    /**
     * Verifies that the device is remembered by the cookie and skips the second factor of a sign-in, while the tokens
     * only report the password ({@code amr [pwd]}, password {@code acr}); that a request with {@code acr_values} for
     * the multi-factor class still renders the TOTP form on the trusted browser (no redirect loop) and, once the code
     * is posted, gets multi-factor tokens; and that the device is asked for the code again after it is revoked.
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
        final var sessionId = second.getId();
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(second).cookie(cookie)
                        .with(AbstractMfaFlow::sendsTheSessionCookie))
                .andExpect(status().is3xxRedirection());
        assertNotEquals(sessionId, second.getId(), "The session id must change when the device is recognised");
        final var trusted = AuthServerFixtures.claimsOf(
                completeAuthorization(secondUri, client, verifier, second).get("access_token").asString());
        assertEquals(List.of(PasswordFactor.AMR_VALUE), strings(trusted.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, trusted.get(ACR).asString());

        final var stepUpVerifier = newVerifier();
        final var stepUpUri = AuthServerFixtures.authorizeUri(client, stepUpVerifier,
                Map.of("acr_values", AuthenticationContextClass.MULTI_FACTOR));
        expectSecondFactorPage(stepUpUri, second);
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(second).cookie(cookie))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"code\"")));
        assertAccepted(postSecondFactor(second, getTools().codeNow(enrolled.id(), 1), false, false));
        final var stepped = AuthServerFixtures.claimsOf(
                completeAuthorization(stepUpUri, client, stepUpVerifier, second).get("access_token").asString());
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, stepped.get(ACR).asString());

        final var device = trustedDevices.findByUser(enrolled.id(), Instant.now()).getFirst();
        assertTrue(trustedDevices.revoke(enrolled.id(), device.id()));

        final var third = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), third);
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(third).cookie(cookie)).andExpect(status().isOk());
    }
    // end::mfa-trusted-device-it[]

    /**
     * Verifies that the cookie carries a signed value and that an unsigned or forged value, even one holding the
     * token of a real trusted device, never skips the second factor: the page is rendered and asks for the code.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenCookieIsUnsignedOrForged_isStillAsked() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var first = new MockHttpSession();
        signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), first);
        final var signed = postSecondFactor(first, getTools().codeNow(enrolled.id(), 0), false, true)
                .getResponse().getCookie(TRUSTED_DEVICE_COOKIE);
        assertNotNull(signed, "The device cookie must be written");
        final var separator = signed.getValue().lastIndexOf('.');
        assertTrue(separator > 0, "The cookie value must be signed");
        final var token = signed.getValue().substring(0, separator);
        final var forgedSignature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(new byte[Base64.getUrlDecoder().decode(signed.getValue().substring(separator + 1))
                        .length]);

        for (final var value : List.of(token, token + "." + forgedSignature)) {
            final var session = new MockHttpSession();
            signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);
            getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session)
                            .cookie(new Cookie(TRUSTED_DEVICE_COOKIE, value)))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("name=\"code\"")));
        }
    }
}

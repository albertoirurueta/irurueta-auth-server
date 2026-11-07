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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;

/**
 * Checks the limits that protect the SMS bill, with settings that make them easy to reach: a message to a country
 * that is not on the allow-list is never sent (neither as a sign-in code nor as the verification code of a phone being
 * enrolled), and once the spend of the window reaches its cap no more messages are sent, while every request is still
 * answered the same so nothing is revealed. Only one test sends messages, because the spend is kept for the whole
 * application context.
 */
@TestPropertySource(properties = {
        "authserver.sms.default-cost-micros=100000",
        "authserver.sms.window-cap-micros=250000",
        "authserver.sms.allowed-countries=ES"})
class OttSmsLimitsIT extends AbstractOttFlow {

    /** Phone number of a country that is not on the allow-list (France). */
    private static final String FRENCH_PREFIX = "+33612";

    /** Number of messages the cap of the window pays for: two of 100000 within 250000. */
    private static final int AFFORDABLE = 2;

    /**
     * Verifies that a sign-in code for a user whose phone is in a country that is not allowed is not sent, and that
     * the answer is the redirect every request gets.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenCountryIsNotAllowed_sendsNothing() throws Exception {
        final var owner = createUserWithPhone(FRENCH_PREFIX + digits().substring(0, 6));

        requestToken(new MockHttpSession(), owner.user().username(), "sms", "code", "login");

        assertEquals(0L, smsCount(owner.phone()));
    }

    /**
     * Verifies that enrolling a number of a country that is not allowed is reported on the page and sends no message,
     * as the page's status says.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void phoneEnrolment_whenCountryIsNotAllowed_reportsItAndSendsNothing() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        getFixtures().signIn(user, session);
        final var before = smsInbox().entries().size();

        getMockMvc().perform(post("/account/phone").session(session).with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).param("phone", "+33 6 12 34 56 78"))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=country-not-allowed"));

        assertEquals(before, smsInbox().entries().size());
    }

    /**
     * Verifies that, once the spend of the window reaches its cap, the messages that would exceed it are not sent
     * while the answer stays the same: two users receive their code, the third does not, and all three get the same
     * redirect.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenSpendReachesTheCap_stopsSendingButAnswersTheSame() throws Exception {
        final var owners = List.of(createUserWithPhone(), createUserWithPhone(), createUserWithPhone());

        for (final var owner : owners) {
            requestToken(new MockHttpSession(), owner.user().username(), "sms", "code", "login");
        }

        final var sent = owners.stream().mapToLong(owner -> smsCount(owner.phone())).sum();
        assertEquals(AFFORDABLE, sent);
        assertEquals(0L, smsCount(owners.getLast().phone()));
    }
}

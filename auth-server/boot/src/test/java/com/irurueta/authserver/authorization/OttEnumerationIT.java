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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that asking for a token never reveals whether an account exists: for a known user, an unknown identifier, a
 * disabled account, an account whose e-mail address is not verified and a user without a phone, the answer of
 * {@code POST /ott/generate} (status, redirect and body) and the page it leads to are identical, and only the known
 * user receives anything.
 */
class OttEnumerationIT extends AbstractOttFlow {

    /** Matches the hidden CSRF field of a page, whose value differs per browser session. */
    private static final Pattern CSRF_FIELD = Pattern.compile("<input[^>]*name=\"_csrf\"[^>]*>");

    /**
     * What a browser sees after asking for a token.
     *
     * @param status   HTTP status of the answer.
     * @param location where the answer redirects to.
     * @param body     body of the answer.
     * @param page     body of the page the redirect leads to, requested in the same browser session.
     */
    private record Observed(int status, String location, String body, String page) {
    }

    /**
     * Verifies that a code asked by e-mail is answered identically for a known user, an unknown identifier, a disabled
     * account and an unverified address, and that only the known user receives a message.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenCodeIsAskedByEmail_answersTheSameForEveryIdentifier() throws Exception {
        assertSameAnswersByEmail("code");
    }

    /**
     * Verifies that a link asked by e-mail is answered identically for a known user, an unknown identifier, a disabled
     * account and an unverified address, and that only the known user receives a message.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenLinkIsAskedByEmail_answersTheSameForEveryIdentifier() throws Exception {
        assertSameAnswersByEmail("link");
    }

    /**
     * Verifies that a code asked by SMS is answered identically for a user with a verified phone, a user without a
     * phone, an unknown identifier and a disabled account, and that only the user with the phone receives a message.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenCodeIsAskedBySms_answersTheSameForEveryIdentifier() throws Exception {
        final var owner = createUserWithPhone();
        final var withoutPhone = getFixtures().createUser();
        final var disabled = createDisabledUserWithPhone();
        final var unknown = "unknown-" + UUID.randomUUID();

        final var known = observe(owner.user().username(), "sms", "code");
        final var others = List.of(observe(withoutPhone.username(), "sms", "code"),
                observe(disabled.user().username(), "sms", "code"), observe(unknown, "sms", "code"));

        others.forEach(other -> assertEquals(known, other));
        assertEquals(1L, awaitSmsCount(owner.phone(), 1L));
        assertEquals(0L, smsCount(disabled.phone()));
    }

    /**
     * Asks for a token by e-mail for four kinds of identifier and checks the answers are the same and the delivery
     * is not.
     *
     * @param kind {@code code} or {@code link}.
     * @throws Exception if a request cannot be performed.
     */
    private void assertSameAnswersByEmail(final String kind) throws Exception {
        final var known = getFixtures().createUser();
        final var disabled = createUserWithStatus(false, true);
        final var unverified = createUserWithStatus(true, false);
        final var unknown = "unknown-" + UUID.randomUUID();

        final var unknownAnswer = observe(unknown, "email", kind);
        final var disabledAnswer = observe(disabled.username(), "email", kind);
        final var unverifiedAnswer = observe(unverified.username(), "email", kind);
        final var knownAnswer = observe(known.username(), "email", kind);

        assertEquals(knownAnswer, unknownAnswer);
        assertEquals(knownAnswer, disabledAnswer);
        assertEquals(knownAnswer, unverifiedAnswer);
        assertNotNull(mailpit().awaitMessageTo(known.email()));
        assertEquals(1, mailpit().countMessagesTo(known.email()));
        assertEquals(0, mailpit().countMessagesTo(disabled.email()));
        assertEquals(0, mailpit().countMessagesTo(unverified.email()));
        assertEquals(0, mailpit().countMessagesTo(unknown + "@example.com"));
    }

    /**
     * Asks for a token with a fresh browser session and records what the browser sees.
     *
     * @param username identifier typed by the user.
     * @param channel  {@code email} or {@code sms}.
     * @param kind     {@code code} or {@code link}.
     * @return the observation.
     * @throws Exception if a request cannot be performed.
     */
    private Observed observe(final String username, final String channel, final String kind) throws Exception {
        final var session = new MockHttpSession();
        final var answer = getMockMvc().perform(generate(session, username, channel, kind, "login")).andReturn()
                .getResponse();
        final var page = getMockMvc().perform(get(LOGIN_OTT).session(session)).andReturn().getResponse()
                .getContentAsString();
        return new Observed(answer.getStatus(), answer.getRedirectedUrl(), answer.getContentAsString(),
                CSRF_FIELD.matcher(page).replaceAll("<csrf/>"));
    }
}

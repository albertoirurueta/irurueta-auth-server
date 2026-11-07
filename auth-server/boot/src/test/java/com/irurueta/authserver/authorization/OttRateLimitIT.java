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
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Checks the rate limits of the one-time token endpoints with small limits: generation and verification are limited
 * per identifier (whatever the client address, and also for an identifier that does not exist, so the limit reveals
 * nothing) and per client address (whatever the identifier), and a limited request is answered {@code 429} with a
 * {@code Retry-After} header and a problem body. The tests use client addresses of their own because the limiter is
 * shared by the whole application context.
 */
@PostgresIT
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "authserver.ott.rate-limit.window=PT15M",
        "authserver.ott.rate-limit.generation-per-client=6",
        "authserver.ott.rate-limit.generation-per-identifier=2",
        "authserver.ott.rate-limit.verification-per-client=5",
        "authserver.ott.rate-limit.verification-per-identifier=3"})
class OttRateLimitIT {

    /** Problem type of a limited request. */
    private static final String PROBLEM_TYPE = "urn:problem:ott:rate-limited";

    /** Generation limit per identifier of this test's settings. */
    private static final int PER_IDENTIFIER = 2;

    /** Generation limit per client address of this test's settings. */
    private static final int PER_CLIENT = 6;

    /** Verification limit per identifier of this test's settings. */
    private static final int VERIFICATION_PER_IDENTIFIER = 3;

    /** Verification limit per client address of this test's settings. */
    private static final int VERIFICATION_PER_CLIENT = 5;

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that asking for tokens for one identifier is limited whatever the client address, and that another
     * identifier is not affected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenIdentifierExceedsTheLimit_isTooManyRequestsFromAnyAddress() throws Exception {
        final var username = "limited-" + UUID.randomUUID();
        for (var attempt = 0; attempt < PER_IDENTIFIER; attempt++) {
            generate(username, "10.10.1." + attempt).andExpect(status().isFound());
        }

        expectLimited(generate(username, "10.10.1.100"));
        generate("other-" + UUID.randomUUID(), "10.10.1.101").andExpect(status().isFound())
                .andExpect(redirectedUrl("/login/ott"));
    }

    /**
     * Verifies that an identifier that does not exist is limited exactly like one that does, so reaching the limit
     * says nothing about an account.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenIdentifierDoesNotExist_isLimitedTheSame() throws Exception {
        final var unknown = "unknown-" + UUID.randomUUID();
        for (var attempt = 0; attempt < PER_IDENTIFIER; attempt++) {
            generate(unknown, "10.10.2." + attempt).andExpect(status().isFound());
        }

        expectLimited(generate(unknown, "10.10.2.100"));
    }

    /**
     * Verifies that asking for tokens from one client address is limited whatever the identifier, and that another
     * address is not affected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generate_whenClientAddressExceedsTheLimit_isTooManyRequestsForAnyIdentifier() throws Exception {
        final var address = "10.10.3.1";
        for (var attempt = 0; attempt < PER_CLIENT; attempt++) {
            generate("user-" + UUID.randomUUID(), address).andExpect(status().isFound());
        }

        expectLimited(generate("user-" + UUID.randomUUID(), address));
        generate("user-" + UUID.randomUUID(), "10.10.3.2").andExpect(status().isFound());
    }

    /**
     * Verifies that posting codes for one identifier is limited whatever the client address: the identifier is the
     * one the browser session asked a token for.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void verify_whenIdentifierExceedsTheLimit_isTooManyRequestsFromAnyAddress() throws Exception {
        final var session = new MockHttpSession();
        generate("verified-" + UUID.randomUUID(), session, "10.10.4.200").andExpect(status().isFound());
        for (var attempt = 0; attempt < VERIFICATION_PER_IDENTIFIER; attempt++) {
            verify(session, "10.10.4." + attempt).andExpect(status().isFound())
                    .andExpect(redirectedUrl("/login/ott?error"));
        }

        expectLimited(verify(session, "10.10.4.100"));
    }

    /**
     * Verifies that posting codes from one client address is limited whatever the browser session.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void verify_whenClientAddressExceedsTheLimit_isTooManyRequests() throws Exception {
        final var address = "10.10.5.1";
        for (var attempt = 0; attempt < VERIFICATION_PER_CLIENT; attempt++) {
            verify(new MockHttpSession(), address).andExpect(status().isFound());
        }

        expectLimited(verify(new MockHttpSession(), address));
        verify(new MockHttpSession(), "10.10.5.2").andExpect(status().isFound());
    }

    /**
     * Asks for a code by e-mail in a new browser session.
     *
     * @param username identifier typed by the user.
     * @param address  client address of the request.
     * @return the answer.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions generate(final String username, final String address) throws Exception {
        return generate(username, new MockHttpSession(), address);
    }

    /**
     * Asks for a code by e-mail.
     *
     * @param username identifier typed by the user.
     * @param session  the browser session.
     * @param address  client address of the request.
     * @return the answer.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions generate(final String username, final MockHttpSession session, final String address)
            throws Exception {
        return mockMvc.perform(post(AbstractOttFlow.GENERATE).session(session).with(csrf())
                .with(request -> from(request, address)).param("username", username).param("channel", "email")
                .param("kind", "code").param("purpose", "login"));
    }

    /**
     * Posts a wrong code.
     *
     * @param session the browser session.
     * @param address client address of the request.
     * @return the answer.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions verify(final MockHttpSession session, final String address) throws Exception {
        return mockMvc.perform(post(AbstractOttFlow.LOGIN_OTT).session(session).with(csrf())
                .with(request -> from(request, address)).param(AbstractOttFlow.TOKEN_FIELD, "000000"));
    }

    /**
     * Fails unless the answer is a limited request.
     *
     * @param answer the answer.
     * @throws Exception if the answer cannot be read.
     */
    private static void expectLimited(final ResultActions answer) throws Exception {
        answer.andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(header().string("Content-Type", startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE)))
                .andExpect(content().string(containsString(PROBLEM_TYPE)));
    }

    /**
     * Makes a request come from another client address.
     *
     * @param request the request.
     * @param address the address.
     * @return the same request.
     */
    private static MockHttpServletRequest from(final MockHttpServletRequest request, final String address) {
        request.setRemoteAddr(address);
        return request;
    }
}

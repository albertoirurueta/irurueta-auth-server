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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks that the attempts to verify a user code are limited per signed-in user: a user code is short, so after a
 * handful of attempts the endpoint answers {@code 429} with a {@code Retry-After} header, whatever the codes were.
 */
@PostgresIT
@AutoConfigureMockMvc
class DeviceVerificationRateLimitIT {

    /** Attempts a user may make in a window, set for the test. */
    private static final int PER_USER = 2;

    /** Path of the verification endpoint. */
    private static final String VERIFICATION = "/oauth2/device_verification";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /**
     * Sets a small limit for the run.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void limits(final DynamicPropertyRegistry registry) {
        registry.add("authserver.device.rate-limit.per-user", () -> PER_USER);
    }

    /**
     * Verifies that the attempt over the limit is refused with {@code 429} and the time to wait.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerification_whenTheUserExceedsTheLimit_answersTooManyRequests() throws Exception {
        final var fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        final var user = fixtures.createUser();
        final var session = new MockHttpSession();
        fixtures.signIn(user, session);
        for (var attempt = 0; attempt < PER_USER; attempt++) {
            mockMvc.perform(post(VERIFICATION).session(session).with(csrf()).param("user_code", "ZZZZ-ZZZZ"))
                    .andExpect(status().is3xxRedirection());
        }

        final var refused = mockMvc.perform(post(VERIFICATION).session(session).with(csrf())
                        .param("user_code", "ZZZZ-ZZZZ"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After")).andReturn();

        assertNotNull(refused.getResponse().getHeader("Retry-After"));
    }
}

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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

import com.irurueta.authserver.authorization.api.web.ApiSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks the API security chain in a web slice with a probe controller. It is an integration test because it starts
 * a Spring context.
 */
@WebMvcTest(controllers = ApiSecurityConfigIT.ProbeController.class)
@Import({ApiSecurityConfig.class, ApiSecurityConfigIT.ProbeController.class})
class ApiSecurityConfigIT {

    /** Path of a protected endpoint. */
    private static final String PROTECTED_PATH = "/api/probe";

    /** Path of an administration endpoint. */
    private static final String ADMIN_PATH = "/api/admin/probe";

    /** MockMvc bound to the web slice. */
    @Autowired
    private MockMvc mockMvc;

    /** Decoder of the bearer tokens. */
    @MockitoBean
    private JwtDecoder jwtDecoder;

    /**
     * Verifies that a request without token is rejected with a bearer challenge.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenNoToken_returns401WithBearerChallenge() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    /**
     * Verifies that an invalid token is rejected with the {@code invalid_token} error of RFC 6750.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsInvalid_returns401InvalidToken() throws Exception {
        when(jwtDecoder.decode("bad")).thenThrow(new BadJwtException("bad token"));

        mockMvc.perform(get(PROTECTED_PATH).header("Authorization", "Bearer bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")));
    }

    /**
     * Verifies that a valid token reaches the endpoint.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsValid_isAllowed() throws Exception {
        mockMvc.perform(get(PROTECTED_PATH).with(jwt()))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that a state-changing request needs no CSRF token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenPostedWithoutCsrf_isAllowed() throws Exception {
        mockMvc.perform(post(PROTECTED_PATH).with(jwt()))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that the API does not create a session.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedEndpoint_whenTokenIsValid_createsNoSession() throws Exception {
        final var session = mockMvc.perform(get(PROTECTED_PATH).with(jwt()))
                .andReturn().getRequest().getSession(false);

        assertNull(session);
    }

    /**
     * Verifies that the public account endpoints need no token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void publicEndpoints_whenNoToken_areNotChallenged() throws Exception {
        mockMvc.perform(post("/api/account/register")).andExpect(status().isOk());
        mockMvc.perform(post("/api/account/password/reset")).andExpect(status().isOk());
        mockMvc.perform(get("/api/account/verify")).andExpect(status().isOk());
    }

    /**
     * Verifies that registration is public only for the documented method.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void register_whenMethodIsGetAndNoToken_returns401() throws Exception {
        mockMvc.perform(get("/api/account/register")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that an administration endpoint accepts the {@code admin} scope.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenHasAdminScope_isAllowed() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).with(jwt().jwt(token -> token.claim("scope", "admin"))))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that an administration endpoint accepts the {@code ADMIN} role. The {@code jwt()} post-processor
     * bypasses the token converter, so the authority is given directly; the converter has its own unit tests.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenHasAdminRole_isAllowed() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk());
    }

    /**
     * Verifies that an administration endpoint rejects a token without the scope or role, with the
     * {@code insufficient_scope} error of RFC 6750.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoint_whenTokenLacksAdminAuthority_returns403() throws Exception {
        mockMvc.perform(get(ADMIN_PATH).with(jwt().jwt(token -> token.claim("scope", "read"))))
                .andExpect(status().isForbidden())
                .andExpect(header().string("WWW-Authenticate", containsString("insufficient_scope")));
    }

    /**
     * Probe endpoints that stand in for the real API. Package-private: the class-level {@code @Import} names it.
     */
    @RestController
    @RequestMapping("/api")
    static class ProbeController {

        /**
         * Answers any request of the probe endpoints.
         *
         * @return an empty body.
         */
        @RequestMapping({"/probe", "/admin/probe", "/account/verify", "/account/register", "/account/password/reset"})
        String probe() {
            return "ok";
        }
    }
}

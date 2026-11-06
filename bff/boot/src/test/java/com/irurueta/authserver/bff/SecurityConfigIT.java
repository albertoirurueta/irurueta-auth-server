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

package com.irurueta.authserver.bff;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of the BFF security filter chain.
 */
@PostgresIT
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the authorization request uses PKCE and asks for the OpenID scopes.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenAuthorizationIsRequested_usesPkce() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/bff"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("code_challenge=")))
                .andExpect(header().string("Location", containsString("code_challenge_method=S256")))
                .andExpect(header().string("Location", containsString("scope=openid%20profile%20documents.read")));
    }

    /**
     * Verifies that a failed sign-in (for example a refused consent) sends the browser back to the SPA, which reports
     * it, instead of to a generated login page.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenSignInFails_redirectsToTheSpaWithAnError() throws Exception {
        mockMvc.perform(get("/login/oauth2/code/bff").param("error", "access_denied").param("state", "unknown"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/?error=signin"));
    }

    /**
     * Verifies that the health endpoint needs no authentication.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenHealthIsRequested_isPublic() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    /**
     * Verifies that a state-changing request without the CSRF token is refused, even from a signed-in user.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenPostLacksCsrfToken_isForbidden() throws Exception {
        mockMvc.perform(post("/bff/logout").with(oidcLogin())).andExpect(status().isForbidden());
    }

    /**
     * Verifies that a signed-in user with the CSRF token can end the session and gets the logout URL.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenPostCarriesCsrfToken_isAccepted() throws Exception {
        mockMvc.perform(post("/bff/logout").with(oidcLogin()).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.logoutUrl").isNotEmpty());
    }

    /**
     * Verifies that an anonymous call to the proxied API is answered 401 instead of redirected to the login page.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenApiIsCalledAnonymously_isUnauthorized() throws Exception {
        mockMvc.perform(get("/api/anything")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that the login endpoint is public and redirects to the authorization request.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenLoginIsRequested_redirectsToAuthorizationRequest() throws Exception {
        mockMvc.perform(get("/bff/login").param("returnTo", "/index.html"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith("/oauth2/authorization/bff")));
    }

    /**
     * Verifies that an open-redirect attempt through {@code returnTo} is refused.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenReturnToIsAnExternalUrl_isBadRequest() throws Exception {
        mockMvc.perform(get("/bff/login").param("returnTo", "https://evil.example/"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/bff/login").param("returnTo", "//evil.example"))
                .andExpect(status().isBadRequest());
    }

    /**
     * Verifies that the CSRF token reaches the SPA in a cookie it can read (not HttpOnly). No security test
     * post-processor is used: those replace the CSRF token repository.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenAnyRequestIsServed_setsReadableXsrfCookie() throws Exception {
        final var cookies = mockMvc.perform(get("/bff/login"))
                .andExpect(status().isFound())
                .andReturn().getResponse().getHeaders("Set-Cookie");

        final var xsrf = cookies.stream().filter(header -> header.startsWith("XSRF-TOKEN=")).findFirst().orElseThrow();
        assertFalse(xsrf.contains("HttpOnly"), xsrf);
    }
}

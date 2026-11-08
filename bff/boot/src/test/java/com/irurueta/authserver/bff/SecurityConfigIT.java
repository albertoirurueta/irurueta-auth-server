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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of the BFF security filter chain.
 */
@PostgresIT
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Path of the logout. */
    private static final String LOGOUT = "/bff/logout";

    /** Name of the session cookie. */
    private static final String SESSION_COOKIE = "__Host-SESSION";

    /** Name of the CSRF cookie. */
    private static final String XSRF_COOKIE = "XSRF-TOKEN";

    /** Authorization request endpoint of the {@code bff} registration. */
    private static final String AUTHORIZATION = "/oauth2/authorization/bff";

    /** Authorization request parameter naming the authentication context classes. */
    private static final String ACR_VALUES_PARAMETER = "acr_values";

    /** Authorization request parameter naming the maximum age of the authentication. */
    private static final String MAX_AGE_PARAMETER = "max_age";

    /** Authentication context class a step-up login asks for. */
    private static final String STEP_UP_ACR = "urn:irurueta:acr:mfa";

    /** Maximum age, in seconds, a step-up login asks for. */
    private static final String STEP_UP_MAX_AGE = "300";

    /** Longest {@code returnTo} the contract allows. */
    private static final int MAX_RETURN_TO_LENGTH = 2048;

    /** Query that counts the stored sessions with a given id. */
    private static final String SESSIONS_WITH_ID = "SELECT COUNT(*) FROM spring_session WHERE session_id = ?";

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /** Access to the session table. */
    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Verifies that the authorization request uses PKCE, asks for the OpenID scopes and for both document scopes (the
     * resource server needs {@code documents.delete} to delete), and carries no step-up parameter unless asked.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenAuthorizationIsRequested_usesPkce() throws Exception {
        mockMvc.perform(get(AUTHORIZATION))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("code_challenge=")))
                .andExpect(header().string("Location", containsString("code_challenge_method=S256")))
                .andExpect(header().string("Location",
                        containsString("scope=openid%20profile%20documents.read%20documents.delete")))
                .andExpect(header().string("Location", not(containsString(ACR_VALUES_PARAMETER))))
                .andExpect(header().string("Location", not(containsString(MAX_AGE_PARAMETER))));
    }

    /**
     * Verifies that a login started for step-up keeps its values in the session and that the next authorization
     * request, and only that one, carries them as {@code acr_values} and {@code max_age}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bffFilterChain_whenLoginAsksForStepUp_addsAcrValuesAndMaxAgeToNextAuthorizationRequestOnly()
            throws Exception {
        final var session = mockMvc.perform(get("/bff/login").param("returnTo", "/")
                        .param("acrValues", STEP_UP_ACR).param("maxAge", STEP_UP_MAX_AGE))
                .andExpect(status().isFound())
                .andReturn().getResponse().getCookie(SESSION_COOKIE);

        mockMvc.perform(get(AUTHORIZATION).cookie(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(ACR_VALUES_PARAMETER + "=" + STEP_UP_ACR)))
                .andExpect(header().string("Location", containsString(MAX_AGE_PARAMETER + "=" + STEP_UP_MAX_AGE)))
                .andExpect(header().string("Location", containsString("code_challenge=")));
        mockMvc.perform(get(AUTHORIZATION).cookie(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString(ACR_VALUES_PARAMETER))));
    }

    /**
     * Verifies that login parameters outside the contract (step-up values of the wrong format or range, a
     * {@code returnTo} longer than allowed) are answered 400, not 500, before anything is kept.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bffFilterChain_whenStepUpValuesAreInvalid_isBadRequest() throws Exception {
        mockMvc.perform(get("/bff/login").param("acrValues", "urn:x\"&evil=1"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/bff/login").param("maxAge", "-1"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/bff/login").param("returnTo", "/" + "a".repeat(MAX_RETURN_TO_LENGTH)))
                .andExpect(status().isBadRequest());
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
        mockMvc.perform(post(LOGOUT).with(oidcLogin())).andExpect(status().isForbidden());
    }

    /**
     * Verifies the sign-out form: the raw value of the {@code XSRF-TOKEN} cookie posted as the {@code _csrf}
     * parameter is accepted (a BREACH-masking handler would reject it), and Spring Security's logout answers a
     * redirect (to the root here: the test provider advertises no end session endpoint), clears the CSRF cookie and
     * deletes the stored session and its cookie. No security test post-processor is used for the CSRF token: those
     * replace the CSRF token repository.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bffFilterChain_whenLogoutFormCarriesRawCsrfParameter_endsSessionAndRedirects() throws Exception {
        final var started = startSession();
        final var session = started.getCookie(SESSION_COOKIE);
        final var xsrf = started.getCookie(XSRF_COOKIE);
        assertEquals(1, storedSessions(session));

        final var logout = mockMvc.perform(post(LOGOUT).cookie(session, xsrf).param("_csrf", xsrf.getValue())
                        .with(oidcLogin()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getResponse();

        assertEquals(0, logout.getCookie(XSRF_COOKIE).getMaxAge());
        assertEquals(0, logout.getCookie(SESSION_COOKIE).getMaxAge());
        assertEquals(0, storedSessions(session));
    }

    /**
     * Verifies that the raw value of the {@code XSRF-TOKEN} cookie is also accepted from the {@code X-XSRF-TOKEN}
     * header, the way the SPA sends it with {@code fetch}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bffFilterChain_whenHeaderCarriesRawCsrfToken_isAccepted() throws Exception {
        final var xsrf = startSession().getCookie(XSRF_COOKIE);

        mockMvc.perform(post(LOGOUT).cookie(xsrf).header("X-XSRF-TOKEN", xsrf.getValue()).with(oidcLogin()))
                .andExpect(status().isFound());
    }

    /**
     * Verifies that a CSRF token that does not match the cookie is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void bffFilterChain_whenCsrfParameterDoesNotMatchCookie_isForbidden() throws Exception {
        final var xsrf = startSession().getCookie(XSRF_COOKIE);

        mockMvc.perform(post(LOGOUT).cookie(xsrf).param("_csrf", "not-" + xsrf.getValue()).with(oidcLogin()))
                .andExpect(status().isForbidden());
    }

    /**
     * Verifies that {@code GET /bff/logout} is not a logout: only the CSRF-protected {@code POST} ends the session.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenLogoutIsRequestedWithGet_isNotHandled() throws Exception {
        mockMvc.perform(get(LOGOUT).with(oidcLogin())).andExpect(status().isNotFound());
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

    /**
     * Starts a session the way the SPA does, through the login endpoint, which also hands out the CSRF cookie.
     *
     * @return the response, carrying the session and CSRF cookies.
     * @throws Exception if the request cannot be performed.
     */
    private MockHttpServletResponse startSession() throws Exception {
        return mockMvc.perform(get("/bff/login")).andExpect(status().isFound()).andReturn().getResponse();
    }

    /**
     * Counts the stored sessions a session cookie points to.
     *
     * @param cookie the session cookie, whose value is the Base64 encoded session id.
     * @return the number of stored sessions with that id.
     */
    private long storedSessions(final Cookie cookie) {
        final var id = new String(Base64.getDecoder().decode(cookie.getValue()), StandardCharsets.UTF_8);
        return jdbcTemplate.queryForObject(SESSIONS_WITH_ID, Long.class, id);
    }
}

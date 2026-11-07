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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.FilterChain;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link OttRateLimitFilter}. */
@ExtendWith(MockitoExtension.class)
class OttRateLimitFilterTest {

    /** Address of the client. */
    private static final String CLIENT = "192.0.2.1";

    /** Seconds to wait. */
    private static final long WAIT_SECONDS = 90;

    /** The limiter. */
    @Mock
    private OttRateLimiter limiter;

    /** The rest of the chain. */
    @Mock
    private FilterChain chain;

    /** Filter under test. */
    private OttRateLimitFilter filter;

    /** The response. */
    private MockHttpServletResponse response;

    /** Creates the filter. */
    @BeforeEach
    void setUp() {
        filter = new OttRateLimitFilter(limiter);
        response = new MockHttpServletResponse();
    }

    /** Clears the security context. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** A token request is counted per client and identifier, lower-cased. */
    @Test
    void doFilter_whenATokenIsRequested_countsItAsGeneration() throws Exception {
        final var request = post("/ott/generate");
        request.setParameter("username", " Alice ");

        filter.doFilter(request, response, chain);

        verify(limiter).checkGeneration(CLIENT, "alice");
        verify(chain).doFilter(request, response);
    }

    /** A token request without an identifier is only limited per client. */
    @Test
    void doFilter_whenATokenIsRequestedWithoutIdentifier_countsTheClientOnly() throws Exception {
        filter.doFilter(post("/ott/generate"), response, chain);

        verify(limiter).checkGeneration(CLIENT, null);
    }

    /** A second-factor token request is counted for the signed-in user, not for the form's identifier. */
    @Test
    void doFilter_whenASecondFactorIsRequested_countsTheSignedInUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", "x", AuthorityUtils.NO_AUTHORITIES));
        final var request = post("/ott/generate");
        request.setParameter("username", "mallory");
        request.setParameter("purpose", "second-factor");

        filter.doFilter(request, response, chain);

        verify(limiter).checkGeneration(CLIENT, "alice");
    }

    /** A code submitted to the sign-in endpoint is counted for the identifier the session asked for. */
    @Test
    void doFilter_whenACodeIsSubmitted_countsItForThePendingIdentifier() throws Exception {
        final var request = post("/login/ott");
        new PendingOtt("Alice", "binding", OttKind.CODE, OttPurpose.LOGIN, OttChannel.EMAIL)
                .saveTo(request.getSession());

        filter.doFilter(request, response, chain);

        verify(limiter).checkVerification(CLIENT, "Alice");
        verify(chain).doFilter(request, response);
    }

    /** A magic link submitted from a browser without a session is only counted per client. */
    @Test
    void doFilter_whenALinkIsSubmittedWithoutSession_countsTheClientOnly() throws Exception {
        filter.doFilter(post("/login/ott"), response, chain);

        verify(limiter).checkVerification(CLIENT, null);
    }

    /** A second-factor code is counted for the signed-in user when nothing is pending. */
    @Test
    void doFilter_whenASecondFactorCodeIsSubmittedWithoutPendingToken_countsTheSignedInUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", "x", AuthorityUtils.NO_AUTHORITIES));

        filter.doFilter(post("/login/second-factor/ott"), response, chain);

        verify(limiter).checkVerification(CLIENT, "alice");
    }

    /** A request over a limit is answered 429 with a problem body and never reaches the chain. */
    @Test
    void doFilter_whenOverTheLimit_answers429WithRetryAfterAndStopsTheChain() throws Exception {
        doThrow(new OttRateLimitExceededException(Duration.ofSeconds(WAIT_SECONDS))).when(limiter)
                .checkGeneration(CLIENT, null);

        filter.doFilter(post("/ott/generate"), response, chain);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS.value(), response.getStatus());
        assertEquals("90", response.getHeader("Retry-After"));
        assertTrue(response.getContentType().startsWith("application/problem+json"));
        assertTrue(response.getContentAsString().contains(OttRateLimitFilter.PROBLEM_TYPE));
        verifyNoInteractions(chain);
    }

    /** Other requests, and gets of the same paths, are not counted. */
    @Test
    void doFilter_whenTheRequestIsNotAnOttPost_doesNotCountIt() throws Exception {
        final var login = post("/login");
        final var page = new MockHttpServletRequest("GET", "/login/ott");
        page.setRemoteAddr(CLIENT);

        filter.doFilter(login, response, chain);
        filter.doFilter(page, response, chain);

        verifyNoInteractions(limiter);
    }

    /**
     * Builds a post.
     *
     * @param path the path.
     * @return the request.
     */
    private static MockHttpServletRequest post(final String path) {
        final var request = new MockHttpServletRequest("POST", path);
        request.setRemoteAddr(CLIENT);
        return request;
    }
}

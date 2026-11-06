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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.FindTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Unit tests of {@link TrustedDeviceFilter}.
 */
@ExtendWith(MockitoExtension.class)
class TrustedDeviceFilterTest {

    /** Authority of the trusted device. */
    private static final String AUTHORITY = TrustedDeviceFactor.AUTHORITY;

    /** The user. */
    private static final String USERNAME = "alice";

    /** The signed value of the cookie. */
    private static final String COOKIE_VALUE = "raw-token.signature";

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Seconds used to build instants around now. */
    private static final long OFFSET_SECONDS = 60;

    /** Finds trusted devices. */
    @Mock
    private FindTrustedDeviceUseCase findTrustedDeviceUseCase;

    /** Adds the factor. */
    @Mock
    private FactorGrantor factorGrantor;

    /** Saves the context. */
    @Mock
    private SecurityContextRepository securityContextRepository;

    /** Resumes the interrupted request. */
    @Mock
    private AuthenticationSuccessHandler resumeHandler;

    /** The rest of the chain. */
    @Mock
    private FilterChain chain;

    /** Filter under test. */
    private TrustedDeviceFilter filter;

    /** The request. */
    private MockHttpServletRequest request;

    /** The response. */
    private MockHttpServletResponse response;

    /** The authentication of the signed-in user, without the second factor. */
    private final Authentication primary =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", AuthorityUtils.NO_AUTHORITIES);

    /** The authentication that holds the second factor. */
    private final Authentication upgraded = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret",
            AuthorityUtils.createAuthorityList(AUTHORITY));

    /**
     * Creates the filter and a request of the second-factor page that carries the cookie, with a signed-in user.
     */
    @BeforeEach
    void setUp() {
        filter = new TrustedDeviceFilter(findTrustedDeviceUseCase, factorGrantor, securityContextRepository,
                resumeHandler, AUTHORITY);
        request = new MockHttpServletRequest("GET", SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH);
        request.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, COOKIE_VALUE));
        response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(primary);
    }

    /**
     * Clears the security context.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a trusted browser that reaches the second-factor page gets the factor, saved, and resumes the
     * interrupted request instead of rendering the page.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenDeviceIsValidOnSecondFactorPage_grantsTheFactorAndResumesTheRequest() throws Exception {
        trust();
        when(factorGrantor.grant(primary, AUTHORITY)).thenReturn(upgraded);

        filter.doFilter(request, response, chain);

        assertSame(upgraded, SecurityContextHolder.getContext().getAuthentication());
        verify(securityContextRepository).saveContext(any(SecurityContext.class), any(), any());
        verify(resumeHandler).onAuthenticationSuccess(request, response, upgraded);
        verifyNoInteractions(chain);
    }

    /**
     * Verifies that the session id changes when a trusted device upgrades the authentication.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenDeviceIsValid_changesTheSessionId() throws Exception {
        final var before = request.getSession(true).getId();
        trust();
        when(factorGrantor.grant(primary, AUTHORITY)).thenReturn(upgraded);

        filter.doFilter(request, response, chain);

        assertNotEquals(before, request.getSession(false).getId());
    }

    /**
     * Verifies that any request other than the second-factor page is let through without looking at the cookie, so
     * a user who never gets the factor is not looked up on every request.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenRequestIsNotTheSecondFactorPage_doesNotLookTheDeviceUp() throws Exception {
        final var other = new MockHttpServletRequest("GET", "/oauth2/consent");
        other.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, COOKIE_VALUE));
        final var post = new MockHttpServletRequest("POST", SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH);
        post.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, COOKIE_VALUE));

        filter.doFilter(other, response, chain);
        filter.doFilter(post, response, chain);

        verify(chain).doFilter(other, response);
        verify(chain).doFilter(post, response);
        verifyNoInteractions(findTrustedDeviceUseCase, factorGrantor, securityContextRepository, resumeHandler);
        assertSame(primary, SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * Verifies that, while a step-up is pending, the second-factor page is rendered (it asks for a real factor) even
     * on a trusted browser, instead of resuming a request the device cannot satisfy.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenStepUpIsPendingOnSecondFactorPage_rendersThePage() throws Exception {
        request.getSession(true).setAttribute(SecondFactorRequiredEntryPoint.STEP_UP_ATTRIBUTE, Boolean.TRUE);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(findTrustedDeviceUseCase, factorGrantor, resumeHandler);
    }

    /**
     * Verifies that an unknown, revoked, forged or unsigned value grants nothing and renders the page.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenDeviceIsNotFound_rendersThePage() throws Exception {
        when(findTrustedDeviceUseCase.execute(USERNAME, COOKIE_VALUE)).thenReturn(Optional.empty());

        filter.doFilter(request, response, chain);

        assertSame(primary, SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(request, response);
        verifyNoInteractions(factorGrantor, securityContextRepository);
        verify(resumeHandler, never()).onAuthenticationSuccess(any(), any(), any(Authentication.class));
    }

    /**
     * Verifies that a request without the cookie is not looked into.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenThereIsNoCookie_continuesTheChain() throws Exception {
        request.setCookies();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(findTrustedDeviceUseCase);
    }

    /**
     * Verifies that a user who already holds the factor is not looked up again.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenFactorIsAlreadyHeld_continuesTheChain() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(upgraded);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(findTrustedDeviceUseCase);
    }

    /**
     * Verifies that nobody signed in, and anonymous users, are ignored.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenNobodyOrAnonymous_continuesTheChain() throws Exception {
        SecurityContextHolder.clearContext();
        filter.doFilter(request, response, chain);
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, response, chain);

        verifyNoInteractions(findTrustedDeviceUseCase);
        assertFalse(SecurityContextHolder.getContext().getAuthentication().getAuthorities().isEmpty());
        assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken);
    }

    /**
     * Makes the use case find a device of the user for the cookie value.
     */
    private void trust() {
        when(findTrustedDeviceUseCase.execute(USERNAME, COOKIE_VALUE)).thenReturn(Optional.of(new TrustedDevice(
                UUID.randomUUID(), UUID.randomUUID(), "hash", null, NOW.plusSeconds(OFFSET_SECONDS), NOW)));
    }
}

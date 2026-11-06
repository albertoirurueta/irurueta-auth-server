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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    /** The raw token of the cookie. */
    private static final String TOKEN = "raw-token";

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Seconds used to build instants around now. */
    private static final long OFFSET_SECONDS = 60;

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** Finds trusted devices. */
    @Mock
    private FindTrustedDeviceUseCase findTrustedDeviceUseCase;

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

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
     * Creates the filter and a request that carries the cookie, with a signed-in user.
     */
    @BeforeEach
    void setUp() {
        filter = new TrustedDeviceFilter(findTrustedDeviceUseCase, userResolver, factorGrantor,
                securityContextRepository, resumeHandler, AUTHORITY);
        request = new MockHttpServletRequest("GET", "/oauth2/consent");
        request.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, TOKEN));
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
     * Verifies that a valid device upgrades the authentication, saves it and lets the request go on.
     */
    @Test
    void doFilter_whenDeviceIsValid_grantsTheFactorAndContinues() throws Exception {
        trust(userId);
        when(factorGrantor.grant(primary, AUTHORITY)).thenReturn(upgraded);

        filter.doFilter(request, response, chain);

        assertSame(upgraded, SecurityContextHolder.getContext().getAuthentication());
        verify(securityContextRepository).saveContext(any(SecurityContext.class), any(), any());
        verify(chain).doFilter(request, response);
        verifyNoInteractions(resumeHandler);
    }

    /**
     * Verifies that the session id changes when a trusted device upgrades the authentication.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenDeviceIsValid_changesTheSessionId() throws Exception {
        final var before = request.getSession(true).getId();
        trust(userId);
        when(factorGrantor.grant(primary, AUTHORITY)).thenReturn(upgraded);

        filter.doFilter(request, response, chain);

        assertNotEquals(before, request.getSession(false).getId());
    }

    /**
     * Verifies that, while a step-up is pending, the second-factor page is rendered (it asks for a real factor) even
     * on a trusted browser, instead of resuming a request the device cannot satisfy.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenStepUpIsPendingOnSecondFactorPage_rendersThePage() throws Exception {
        request = new MockHttpServletRequest("GET", SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH);
        request.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, TOKEN));
        request.getSession(true).setAttribute(SecondFactorRequiredEntryPoint.STEP_UP_ATTRIBUTE, Boolean.TRUE);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(findTrustedDeviceUseCase, factorGrantor, resumeHandler);
    }

    /**
     * Verifies that a trusted browser that reaches the second-factor page resumes the interrupted request.
     */
    @Test
    void doFilter_whenDeviceIsValidOnSecondFactorPage_resumesTheRequest() throws Exception {
        request = new MockHttpServletRequest("GET", SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH);
        request.setCookies(new Cookie(TrustedDeviceCookieWriter.COOKIE_NAME, TOKEN));
        trust(userId);
        when(factorGrantor.grant(primary, AUTHORITY)).thenReturn(upgraded);

        filter.doFilter(request, response, chain);

        verify(resumeHandler).onAuthenticationSuccess(request, response, upgraded);
        verifyNoInteractions(chain);
    }

    /**
     * Verifies that an unknown or revoked device grants nothing.
     */
    @Test
    void doFilter_whenDeviceIsUnknown_leavesTheAuthenticationAlone() throws Exception {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(findTrustedDeviceUseCase.execute(userId, TOKEN)).thenReturn(Optional.empty());

        filter.doFilter(request, response, chain);

        assertSame(primary, SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(request, response);
        verifyNoInteractions(factorGrantor, securityContextRepository);
    }

    /**
     * Verifies that a device of another user grants nothing.
     */
    @Test
    void doFilter_whenDeviceBelongsToAnotherUser_leavesTheAuthenticationAlone() throws Exception {
        trust(UUID.randomUUID());

        filter.doFilter(request, response, chain);

        assertSame(primary, SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(factorGrantor);
    }

    /**
     * Verifies that a cookie of a user that no longer exists grants nothing.
     */
    @Test
    void doFilter_whenAccountIsMissing_leavesTheAuthenticationAlone() throws Exception {
        when(userResolver.userIdOf(USERNAME)).thenThrow(new UsernameNotFoundException("gone"));

        filter.doFilter(request, response, chain);

        assertSame(primary, SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(request, response);
        verifyNoInteractions(findTrustedDeviceUseCase);
    }

    /**
     * Verifies that a request without the cookie is not looked into.
     */
    @Test
    void doFilter_whenThereIsNoCookie_continuesTheChain() throws Exception {
        request.setCookies();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(userResolver, findTrustedDeviceUseCase);
    }

    /**
     * Verifies that a user who already holds the factor is not looked up again.
     */
    @Test
    void doFilter_whenFactorIsAlreadyHeld_continuesTheChain() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(upgraded);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(userResolver, findTrustedDeviceUseCase);
    }

    /**
     * Verifies that nobody signed in, and anonymous users, are ignored.
     */
    @Test
    void doFilter_whenNobodyOrAnonymous_continuesTheChain() throws Exception {
        SecurityContextHolder.clearContext();
        filter.doFilter(request, response, chain);
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, response, chain);

        verifyNoInteractions(userResolver, findTrustedDeviceUseCase);
        assertFalse(SecurityContextHolder.getContext().getAuthentication().getAuthorities().isEmpty());
        assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken);
    }

    /**
     * Makes the use case find a device.
     *
     * @param owner the owner of the device.
     */
    private void trust(final UUID owner) {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(findTrustedDeviceUseCase.execute(userId, TOKEN)).thenReturn(Optional.of(
                new TrustedDevice(UUID.randomUUID(), owner, "hash", null, NOW.plusSeconds(OFFSET_SECONDS), NOW)));
    }
}

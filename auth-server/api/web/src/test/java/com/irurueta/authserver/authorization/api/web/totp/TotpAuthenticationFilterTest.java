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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceCookieWriter;
import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.application.mfa.CreatedTrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;

/**
 * Unit tests of {@link TotpAuthenticationFilter}.
 */
@ExtendWith(MockitoExtension.class)
class TotpAuthenticationFilterTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** Length of the user agent used to test truncation. */
    private static final int LONG_USER_AGENT = 400;

    /** Manager that verifies the code. */
    @Mock
    private AuthenticationManager authenticationManager;

    /** Remembers devices. */
    @Mock
    private CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Writes the device cookie. */
    @Mock
    private TrustedDeviceCookieWriter cookieWriter;

    /** Keeps the recovery codes of an enrolment; real, so the session round trip is exercised. */
    @Spy
    private PendingRecoveryCodes pendingRecoveryCodes = new PendingRecoveryCodes();

    /** The rest of the chain. */
    @Mock
    private FilterChain chain;

    /** Filter under test. */
    private TotpAuthenticationFilter filter;

    /** The request. */
    private MockHttpServletRequest request;

    /** The response. */
    private MockHttpServletResponse response;

    /** The authentication the user already holds. */
    private final Authentication primary =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", AuthorityUtils.NO_AUTHORITIES);

    /**
     * Creates the filter and a post to the endpoint, with a signed-in user.
     */
    @BeforeEach
    void setUp() {
        filter = new TotpAuthenticationFilter(authenticationManager, createTrustedDeviceUseCase, userResolver,
                cookieWriter, pendingRecoveryCodes);
        request = new MockHttpServletRequest("POST", TotpAuthenticationFilter.TOTP_PATH);
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
     * Verifies that the code is trimmed and handed to the manager as a TOTP request.
     */
    @Test
    void attemptAuthentication_whenCodeIsPosted_asksTheManagerToVerifyIt() {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, " 123456 ");
        final var verified = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(verified);

        final var result = filter.attemptAuthentication(request, response);

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        final var sent = (TotpAuthenticationToken) captor.getValue();
        assertSame(verified, result);
        assertSame(primary, sent.primary());
        assertEquals("123456", sent.getCredentials());
        assertEquals(TotpCodeKind.TOTP, sent.kind());
        assertFalse(pendingRecoveryCodes.isPending(request));
    }

    /**
     * Verifies that a missing code is sent as an empty one and that the recovery field flags a recovery code.
     */
    @Test
    void attemptAuthentication_whenRecoveryWithoutCode_sendsEmptyRecoveryRequest() {
        request.setParameter(TotpAuthenticationFilter.RECOVERY_PARAMETER, "true");

        filter.attemptAuthentication(request, response);

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        final var sent = (TotpAuthenticationToken) captor.getValue();
        assertEquals("", sent.getCredentials());
        assertEquals(TotpCodeKind.RECOVERY, sent.kind());
    }

    /**
     * Verifies that the enrolment field flags an enrolment code, and that the recovery codes the verification issues
     * are kept in the session.
     */
    @Test
    void attemptAuthentication_whenEnrolmentIsConfirmed_keepsTheRecoveryCodesInTheSession() {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        request.setParameter(TotpAuthenticationFilter.ENROLL_PARAMETER, "true");
        request.setParameter(TotpAuthenticationFilter.RECOVERY_PARAMETER, "true");
        doAnswer(invocation -> {
            invocation.<TotpAuthenticationToken>getArgument(0).issueRecoveryCodes(List.of("AAAAAAAAAA"));
            return primary;
        }).when(authenticationManager).authenticate(any());

        filter.attemptAuthentication(request, response);

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        assertEquals(TotpCodeKind.ENROLMENT, ((TotpAuthenticationToken) captor.getValue()).kind());
        assertEquals(List.of("AAAAAAAAAA"), pendingRecoveryCodes.take(request));
    }

    /**
     * Verifies that nobody signed in is rejected.
     */
    @Test
    void attemptAuthentication_whenNobodyIsSignedIn_throwsInsufficientAuthenticationException() {
        SecurityContextHolder.clearContext();

        assertThrows(InsufficientAuthenticationException.class, () -> filter.attemptAuthentication(request, response));
        verifyNoInteractions(authenticationManager);
    }

    /**
     * Verifies that an anonymous user is rejected.
     */
    @Test
    void attemptAuthentication_whenAnonymous_throwsInsufficientAuthenticationException() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThrows(InsufficientAuthenticationException.class, () -> filter.attemptAuthentication(request, response));
    }

    /**
     * Verifies that a failure of the manager is not swallowed.
     */
    @Test
    void attemptAuthentication_whenCodeIsWrong_propagatesTheFailure() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("wrong"));

        assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, response));
    }

    /**
     * Verifies the whole flow: a verified code is saved to the session and the browser is redirected, with no device
     * remembered when the box is not checked.
     */
    @Test
    void doFilter_whenCodeIsAccepted_savesTheAuthenticationAndRedirects() throws Exception {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        final var verified = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret",
                AuthorityUtils.createAuthorityList(TotpFactor.AUTHORITY));
        when(authenticationManager.authenticate(any())).thenReturn(verified);

        filter.doFilter(request, response, chain);

        assertEquals("/", response.getRedirectedUrl());
        assertNotNull(request.getSession(false));
        assertSame(verified, SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(createTrustedDeviceUseCase, cookieWriter, chain);
    }

    /**
     * Verifies that the session id changes once the second factor is verified, against session fixation.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenCodeIsAccepted_changesTheSessionId() throws Exception {
        final var before = request.getSession(true).getId();
        // the browser sent the cookie of this session, as a real one does
        request.setRequestedSessionIdValid(true);
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        when(authenticationManager.authenticate(any())).thenReturn(primary);

        filter.doFilter(request, response, chain);

        assertNotEquals(before, request.getSession(false).getId());
    }

    /**
     * Verifies that a confirmed enrolment sends the browser to the page that shows the recovery codes once.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenEnrolmentIsConfirmed_redirectsToTheRecoveryCodesPage() throws Exception {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        request.setParameter(TotpAuthenticationFilter.ENROLL_PARAMETER, "true");
        doAnswer(invocation -> {
            invocation.<TotpAuthenticationToken>getArgument(0).issueRecoveryCodes(List.of("AAAAAAAAAA"));
            return primary;
        }).when(authenticationManager).authenticate(any());

        filter.doFilter(request, response, chain);

        assertEquals(RecoveryCodesPageController.RECOVERY_CODES_PATH, response.getRedirectedUrl());
        assertTrue(pendingRecoveryCodes.isPending(request));
    }

    /**
     * Verifies that a device is remembered and its cookie written when the user asks for it, and that the browser
     * agent is cut to the size that is stored.
     */
    @Test
    void doFilter_whenRememberIsChecked_remembersTheDevice() throws Exception {
        final var userId = UUID.randomUUID();
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        request.setParameter(TotpAuthenticationFilter.REMEMBER_PARAMETER, "on");
        request.addHeader("User-Agent", "a".repeat(LONG_USER_AGENT));
        final var verified = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret",
                AuthorityUtils.createAuthorityList(TotpFactor.AUTHORITY));
        final var created = createdDevice();
        when(authenticationManager.authenticate(any())).thenReturn(verified);
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(createTrustedDeviceUseCase.execute(any(), any(), any())).thenReturn(created);

        filter.doFilter(request, response, chain);

        final var agent = ArgumentCaptor.<String>captor();
        verify(createTrustedDeviceUseCase).execute(any(), any(), agent.capture());
        assertEquals(TotpAuthenticationFilter.MAX_USER_AGENT_LENGTH, agent.getValue().length());
        verify(cookieWriter).write(response, created);
        assertEquals("/", response.getRedirectedUrl());
    }

    /**
     * Verifies that a request without user agent remembers the device with no description.
     */
    @Test
    void doFilter_whenRememberIsCheckedWithoutUserAgent_describesTheDeviceWithNull() throws Exception {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        request.setParameter(TotpAuthenticationFilter.REMEMBER_PARAMETER, "on");
        final var verified = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret",
                AuthorityUtils.NO_AUTHORITIES);
        when(authenticationManager.authenticate(any())).thenReturn(verified);
        when(userResolver.userIdOf(USERNAME)).thenReturn(UUID.randomUUID());
        when(createTrustedDeviceUseCase.execute(any(), any(), any())).thenReturn(createdDevice());

        filter.doFilter(request, response, chain);

        final var agent = ArgumentCaptor.<String>captor();
        verify(createTrustedDeviceUseCase).execute(any(), any(), agent.capture());
        assertNull(agent.getValue());
    }

    /**
     * Verifies that a short user agent is kept as it is.
     */
    @Test
    void doFilter_whenUserAgentIsShort_keepsItWhole() throws Exception {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "123456");
        request.setParameter(TotpAuthenticationFilter.REMEMBER_PARAMETER, "on");
        request.addHeader("User-Agent", "Firefox");
        when(authenticationManager.authenticate(any())).thenReturn(primary);
        when(userResolver.userIdOf(USERNAME)).thenReturn(UUID.randomUUID());
        when(createTrustedDeviceUseCase.execute(any(), any(), any())).thenReturn(createdDevice());

        filter.doFilter(request, response, chain);

        verify(createTrustedDeviceUseCase).execute(any(), any(), eq("Firefox"));
    }

    /**
     * Verifies that a wrong code sends the browser back to the second-factor page with the error flag.
     */
    @Test
    void doFilter_whenCodeIsWrong_redirectsBackWithError() throws Exception {
        request.setParameter(TotpAuthenticationFilter.CODE_PARAMETER, "000000");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("wrong"));

        filter.doFilter(request, response, chain);

        assertEquals("/login/second-factor?error", response.getRedirectedUrl());
        assertNotNull(request.getSession(false).getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));
        verifyNoInteractions(createTrustedDeviceUseCase);
    }

    /**
     * Verifies that another path is passed down the chain untouched.
     */
    @Test
    void doFilter_whenPathDiffers_continuesTheChain() throws Exception {
        final var other = new MockHttpServletRequest("POST", "/other");

        filter.doFilter(other, response, chain);

        verify(chain).doFilter(other, response);
        verifyNoInteractions(authenticationManager);
    }

    /**
     * Builds a remembered device.
     *
     * @return the device and its raw token.
     */
    private static CreatedTrustedDevice createdDevice() {
        final var now = Instant.now();
        return new CreatedTrustedDevice(
                new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), "hash", null, now.plusSeconds(1), now),
                "token");
    }
}

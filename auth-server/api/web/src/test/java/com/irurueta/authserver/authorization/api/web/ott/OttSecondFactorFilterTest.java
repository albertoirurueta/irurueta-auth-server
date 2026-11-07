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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link OttSecondFactorFilter}. */
@ExtendWith(MockitoExtension.class)
class OttSecondFactorFilterTest {

    /** Manager that verifies the code. */
    @Mock
    private AuthenticationManager authenticationManager;

    /** The rest of the chain. */
    @Mock
    private FilterChain chain;

    /** Filter under test. */
    private OttSecondFactorFilter filter;

    /** The request. */
    private MockHttpServletRequest request;

    /** The response. */
    private MockHttpServletResponse response;

    /** The authentication the user already holds. */
    private final Authentication primary = UsernamePasswordAuthenticationToken.authenticated("alice", "x",
            List.of(FactorGrantedAuthority.fromAuthority("FACTOR_PASSWORD")));

    /** Creates the filter and a post to the endpoint, with a signed-in user. */
    @BeforeEach
    void setUp() {
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY)));
        filter = new OttSecondFactorFilter(authenticationManager, new PrimaryFactorSession(registry));
        request = new MockHttpServletRequest("POST", OttSecondFactorFilter.SECOND_FACTOR_OTT_PATH);
        response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(primary);
    }

    /** Clears the security context. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** The code is trimmed and handed to the manager with the binding of the session. */
    @Test
    void attemptAuthentication_whenCodeIsPosted_asksTheManagerToVerifyItWithTheBinding() {
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.SECOND_FACTOR, OttChannel.EMAIL)
                .saveTo(request.getSession());
        request.setParameter(OttSecondFactorFilter.CODE_PARAMETER, " 123456 ");
        final var verified = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(verified);

        final var result = filter.attemptAuthentication(request, response);

        assertSame(verified, result);
        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        final var token = (OttSecondFactorToken) captor.getValue();
        assertSame(primary, token.primary());
        assertEquals("123456", token.getCredentials());
        assertEquals("binding", token.bindingId());
    }

    /** A post without a code or a pending token is verified with empty values, so it fails like a wrong code. */
    @Test
    void attemptAuthentication_whenNothingWasRequested_verifiesEmptyValues() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("no"));

        assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, response));

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        final var token = (OttSecondFactorToken) captor.getValue();
        assertEquals("", token.getCredentials());
        assertEquals("", token.bindingId());
    }

    /** Nobody can post without a primary factor. */
    @Test
    void attemptAuthentication_whenNoPrimaryFactorWasPresented_throwsInsufficientAuthenticationException() {
        SecurityContextHolder.clearContext();

        assertThrows(InsufficientAuthenticationException.class, () -> filter.attemptAuthentication(request, response));
        verifyNoInteractions(authenticationManager);
    }

    /** A verified code saves the authentication, changes the session id and forgets the pending token. */
    @Test
    void doFilter_whenTheCodeIsAccepted_changesTheSessionIdAndForgetsThePendingToken() throws Exception {
        final var session = request.getSession();
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.SECOND_FACTOR, OttChannel.EMAIL)
                .saveTo(session);
        final var before = session.getId();
        request.setRequestedSessionIdValid(true);
        request.setParameter(OttSecondFactorFilter.CODE_PARAMETER, "123456");
        final var verified = UsernamePasswordAuthenticationToken.authenticated("alice", "x", List.of(
                FactorGrantedAuthority.fromAuthority("FACTOR_PASSWORD"),
                FactorGrantedAuthority.fromAuthority("FACTOR_OTT_EMAIL_2FA")));
        when(authenticationManager.authenticate(any())).thenReturn(verified);

        filter.doFilter(request, response, chain);

        assertEquals("/", response.getRedirectedUrl());
        assertNotEquals(before, request.getSession(false).getId());
        assertTrue(PendingOtt.of(request).isEmpty());
        assertSame(verified, SecurityContextHolder.getContext().getAuthentication());
    }

    /** A wrong code goes back to the page where it is typed. */
    @Test
    void doFilter_whenTheCodeIsWrong_redirectsBackWithError() throws Exception {
        request.setParameter(OttSecondFactorFilter.CODE_PARAMETER, "000000");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("no"));

        filter.doFilter(request, response, chain);

        assertEquals("/login/ott?error", response.getRedirectedUrl());
    }
}

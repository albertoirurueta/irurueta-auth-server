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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Unit tests of {@link X509AuthenticationSuccessHandler}.
 */
@ExtendWith(MockitoExtension.class)
class X509AuthenticationSuccessHandlerTest {

    /** Instant of the sign-in. */
    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");

    /** Instant the password was presented. */
    private static final Instant EARLIER = NOW.minusSeconds(60);

    /** Saves the security context. */
    @Mock
    private SecurityContextRepository securityContextRepository;

    /** Resumes the interrupted request. */
    @Mock
    private AuthenticationSuccessHandler delegate;

    /** Changes the session id. */
    @Mock
    private SessionAuthenticationStrategy sessionStrategy;

    /**
     * Clears the security context.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the framework's authentication is replaced by the ordinary authentication of the account, with the
     * factor stamped and the authorities of the session kept.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenCertificateSignsIn_replacesTheAuthenticationAndGrantsTheFactor()
            throws Exception {
        final var handler = handler();
        handler.setSessionAuthenticationStrategy(sessionStrategy);
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, preAuthenticated());

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(sessionStrategy).onAuthentication(captor.capture(), org.mockito.ArgumentMatchers.eq(request),
                org.mockito.ArgumentMatchers.eq(response));
        final var signedIn = captor.getValue();
        assertInstanceOf(UsernamePasswordAuthenticationToken.class, signedIn);
        assertTrue(signedIn.isAuthenticated());
        assertEquals("alice", ((User) signedIn.getPrincipal()).getUsername());
        final var authorities = signedIn.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        assertEquals(List.of("ROLE_USER", "FACTOR_PASSWORD", "FACTOR_X509"), authorities);
        final var x509 = signedIn.getAuthorities().stream()
                .filter(authority -> "FACTOR_X509".equals(authority.getAuthority())).findFirst().orElseThrow();
        assertEquals(NOW, assertInstanceOf(FactorGrantedAuthority.class, x509).getIssuedAt());
        final var password = signedIn.getAuthorities().stream()
                .filter(authority -> "FACTOR_PASSWORD".equals(authority.getAuthority())).findFirst().orElseThrow();
        assertEquals(EARLIER, assertInstanceOf(FactorGrantedAuthority.class, password).getIssuedAt());
        assertSame(signedIn, SecurityContextHolder.getContext().getAuthentication());
        final var contextCaptor = ArgumentCaptor.<SecurityContext>captor();
        verify(securityContextRepository).saveContext(contextCaptor.capture(), org.mockito.ArgumentMatchers.eq(request),
                org.mockito.ArgumentMatchers.eq(response));
        assertSame(signedIn, contextCaptor.getValue().getAuthentication());
        verify(delegate).onAuthenticationSuccess(request, response, signedIn);
    }

    /**
     * Verifies that without a session strategy the sign-in still completes.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenNoSessionStrategyIsSet_stillCompletesTheSignIn() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        handler().onAuthenticationSuccess(request, response, preAuthenticated());

        verify(delegate).onAuthenticationSuccess(org.mockito.ArgumentMatchers.eq(request),
                org.mockito.ArgumentMatchers.eq(response), org.mockito.ArgumentMatchers.any());
    }

    /**
     * Builds the handler, with a real grantor on a fixed clock.
     *
     * @return the handler.
     */
    private X509AuthenticationSuccessHandler handler() {
        return new X509AuthenticationSuccessHandler(new FactorGrantor(Clock.fixed(NOW, ZoneOffset.UTC)),
                securityContextRepository, delegate);
    }

    /**
     * Builds the authentication the framework produces: the account's authority, the plain factor authority its
     * provider adds, and the factor the session already had.
     *
     * @return the authentication.
     */
    private static Authentication preAuthenticated() {
        final var user = User.withUsername("alice").password("x").authorities("ROLE_USER").build();
        return new PreAuthenticatedAuthenticationToken(user, null, List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                FactorGrantedAuthority.withAuthority("FACTOR_PASSWORD").issuedAt(EARLIER).build(),
                new SimpleGrantedAuthority(FactorGrantedAuthority.X509_AUTHORITY)));
    }
}

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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Unit tests of {@link FederatedAuthenticationSuccessHandler}.
 */
@ExtendWith(MockitoExtension.class)
class FederatedAuthenticationSuccessHandlerTest {

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Chooses the factor. */
    @Mock
    private FederatedFactorSelector factorSelector;

    /** Saves the security context. */
    @Mock
    private SecurityContextRepository securityContextRepository;

    /** The handler that resumes the saved request. */
    @Mock
    private AuthenticationSuccessHandler delegate;

    /** Real grantor over a fixed clock. */
    private final FactorGrantor factorGrantor = new FactorGrantor(Clock.fixed(NOW, ZoneOffset.UTC));

    /**
     * Clears the security context the handler sets.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the factor is granted, the granted authentication becomes the current one and is saved again, and
     * the usual handler continues with it.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenSignInIsFederated_grantsTheFactorSavesTheContextAndContinues() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var token = token();
        when(factorSelector.authorityOf(token)).thenReturn(FederatedFactor.AUTHORITY);

        handler().onAuthenticationSuccess(request, response, token);

        final var contextCaptor = ArgumentCaptor.<SecurityContext>captor();
        verify(securityContextRepository).saveContext(contextCaptor.capture(), eq(request), eq(response));
        final var granted = contextCaptor.getValue().getAuthentication();
        assertEquals("alice", granted.getName());
        assertTrue(granted.getAuthorities().stream().filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .anyMatch(factor -> FederatedFactor.AUTHORITY.equals(factor.getAuthority())
                        && NOW.equals(factor.getIssuedAt())));
        assertTrue(granted.getAuthorities().stream().anyMatch(a -> "ROLE_USER".equals(a.getAuthority())));
        assertSame(granted, SecurityContextHolder.getContext().getAuthentication());
        verify(delegate).onAuthenticationSuccess(request, response, granted);
    }

    /**
     * Verifies that an authentication of another kind is passed on untouched.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenAuthenticationIsOfAnotherKind_continuesWithItUntouched() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var other = new TestingAuthenticationToken("bob", "secret");

        handler().onAuthenticationSuccess(request, response, other);

        verify(delegate).onAuthenticationSuccess(request, response, other);
        verifyNoInteractions(securityContextRepository);
    }

    /**
     * Builds the handler under test.
     *
     * @return the handler.
     */
    private FederatedAuthenticationSuccessHandler handler() {
        return new FederatedAuthenticationSuccessHandler(factorGrantor, factorSelector, securityContextRepository,
                delegate);
    }

    /**
     * Builds the authentication of a sign-in.
     *
     * @return the authentication.
     */
    private static OAuth2AuthenticationToken token() {
        final var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("local_username", "alice"), "local_username");
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), "google");
    }
}

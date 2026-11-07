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
package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests of {@link PasskeySecondFactorLockoutFilter}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeySecondFactorLockoutFilterTest {

    /** Name of the signed-in user. */
    private static final String USERNAME = "alice";

    /** Path that verifies an authentication ceremony. */
    private static final String AUTHENTICATION = "/login/webauthn";

    /** Resolves the account of the signed-in user. */
    @Mock
    private SecondFactorUserResolver secondFactorUserResolver;

    /** Tells whether the second factor of a user is locked. */
    @Mock
    private CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Rest of the chain. */
    @Mock
    private FilterChain chain;

    /** Filter under test. */
    @InjectMocks
    private PasskeySecondFactorLockoutFilter filter;

    /**
     * Clears the security context the tests set.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a passkey completing the second factor of a locked user is answered {@code 401} and stops the
     * chain.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenSignedInUserIsLocked_answersUnauthorizedAndStopsTheChain() throws Exception {
        final var userId = UUID.randomUUID();
        signIn(signedInUser());
        when(secondFactorUserResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(true);
        final var response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("POST", AUTHENTICATION), response, chain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        verifyNoInteractions(chain);
    }

    /**
     * Verifies that a passkey completing the second factor of a user that is not locked goes on.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenSignedInUserIsNotLocked_continuesTheChain() throws Exception {
        final var userId = UUID.randomUUID();
        signIn(signedInUser());
        when(secondFactorUserResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(false);
        final var request = new MockHttpServletRequest("POST", AUTHENTICATION);
        final var response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    /**
     * Verifies that a session whose account no longer exists is refused.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenAccountOfTheSessionIsGone_answersUnauthorized() throws Exception {
        signIn(signedInUser());
        when(secondFactorUserResolver.userIdOf(USERNAME)).thenThrow(new UsernameNotFoundException(USERNAME));
        final var response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("POST", AUTHENTICATION), response, chain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        verifyNoInteractions(chain, checkSecondFactorLockoutUseCase);
    }

    /**
     * Verifies that a passwordless sign-in (an anonymous session) is never checked: there is no account yet.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenSessionIsAnonymous_continuesWithoutCheckingTheLockout() throws Exception {
        signIn(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        final var request = new MockHttpServletRequest("POST", AUTHENTICATION);
        final var response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(secondFactorUserResolver, checkSecondFactorLockoutUseCase);
    }

    /**
     * Verifies that any other request, including a get of the same path, is never checked.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenRequestIsNotTheAuthenticationPost_continuesWithoutCheckingTheLockout() throws Exception {
        signIn(signedInUser());
        for (final var request : List.of(new MockHttpServletRequest("GET", AUTHENTICATION),
                new MockHttpServletRequest("POST", "/login"))) {
            final var response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            verify(chain).doFilter(request, response);
        }
        verifyNoInteractions(secondFactorUserResolver, checkSecondFactorLockoutUseCase);
    }

    /**
     * Builds the authentication of a user who presented the password.
     *
     * @return the authentication.
     */
    private static Authentication signedInUser() {
        return UsernamePasswordAuthenticationToken.authenticated(USERNAME, null,
                AuthorityUtils.createAuthorityList("FACTOR_PASSWORD"));
    }

    /**
     * Puts an authentication in the security context.
     *
     * @param authentication the authentication.
     */
    private static void signIn(final Authentication authentication) {
        final var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }
}

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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 * Unit tests of {@link DeviceVerificationRequestGuard}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceVerificationRequestGuardTest {

    /** Name of the signed-in user. */
    private static final String USER = "alice";

    /** Identifier of the client the consent decision names. */
    private static final String CLIENT_ID = "device-client";

    /** Address of the caller. */
    private static final String ADDRESS = "192.0.2.7";

    /** Limits the attempts. */
    @Mock
    private DeviceVerificationRateLimiter rateLimiter;

    /** Applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Guard under test. */
    @InjectMocks
    private DeviceVerificationRequestGuard guard;

    /**
     * Clears the security context.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a request nobody is signed in for is left to the chain's own authentication.
     */
    @Test
    void convert_whenNobodyIsSignedIn_returnsNullWithoutChecks() {
        assertNull(guard.convert(request()));

        verifyNoInteractions(rateLimiter, authorizationManager);
    }

    /**
     * Verifies that an anonymous request is not counted.
     */
    @Test
    void convert_whenTheUserIsAnonymous_returnsNullWithoutChecks() {
        final var anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        SecurityContextHolder.setContext(new SecurityContextImpl(anonymous));

        assertNull(guard.convert(request()));

        verifyNoInteractions(rateLimiter, authorizationManager);
    }

    /**
     * Verifies that an attempt of a user who satisfies the policy is counted and let through.
     */
    @Test
    void convert_whenThePolicyIsSatisfied_countsTheAttemptAndReturnsNull() {
        final var user = signIn();
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request()));

        verify(rateLimiter).check(ADDRESS, USER);
    }

    /**
     * Verifies that a client that requires multi-factor authentication is taken into account.
     */
    @Test
    void convert_whenTheClientRequiresMfa_evaluatesThePolicyWithIt() {
        final var user = signIn();
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(true);
        when(authorizationManager.evaluate(user, true)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request()));
    }

    /**
     * Verifies that a user who owes a second factor is sent to the second-factor page.
     */
    @Test
    void convert_whenASecondFactorIsOwed_throwsSecondFactorRequired() {
        final var user = signIn();
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(false));

        assertThrows(SecondFactorRequiredException.class, () -> guard.convert(request()));
    }

    /**
     * Verifies that too many attempts stop the request before the policy is looked at.
     */
    @Test
    void convert_whenTheLimitIsExceeded_propagatesTheFailure() {
        signIn();
        final var limited = new DeviceVerificationRateLimitedException(Duration.ofSeconds(1));
        doThrow(limited).when(rateLimiter).check(ADDRESS, USER);

        final var thrown = assertThrows(DeviceVerificationRateLimitedException.class,
                () -> guard.convert(request()));

        assertSame(limited, thrown);
        verify(authorizationManager, never()).evaluate(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyBoolean());
    }

    /**
     * Builds the request of a caller.
     *
     * @return the request, which names the client.
     */
    private static MockHttpServletRequest request() {
        final var request = new MockHttpServletRequest("POST", "/oauth2/device_verification");
        request.setRemoteAddr(ADDRESS);
        request.setParameter("client_id", CLIENT_ID);
        return request;
    }

    /**
     * Signs the user in.
     *
     * @return the authentication.
     */
    private static UsernamePasswordAuthenticationToken signIn() {
        final var user = UsernamePasswordAuthenticationToken.authenticated(USER, null, List.of());
        SecurityContextHolder.setContext(new SecurityContextImpl(user));
        return user;
    }
}

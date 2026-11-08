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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

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

    /** Identifier of the client the device authorization of the user code was issued to. */
    private static final String DEVICE_CLIENT_ID = "stored-device-client";

    /** Internal identifier of that client. */
    private static final String REGISTERED_ID = "registered-1";

    /** User code as the framework stores it. */
    private static final String USER_CODE = "BCDF-GHJK";

    /** Limits the attempts. */
    @Mock
    private DeviceVerificationRateLimiter rateLimiter;

    /** Applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Finds the device authorization of a user code. */
    @Mock
    private OAuth2AuthorizationService authorizationService;

    /** Finds the client of a device authorization. */
    @Mock
    private RegisteredClientRepository registeredClientRepository;

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
        verify(authorizationManager, never()).evaluate(any(), anyBoolean());
    }

    /**
     * Verifies that the client of the device authorization stored for the user code is the one whose policy applies,
     * whatever the code looks like as typed (lower case, spaces), even when the request names no client.
     */
    @Test
    void convert_whenTheUserCodeHasADeviceAuthorization_appliesThePolicyOfItsClient() {
        final var user = signIn();
        final var request = new MockHttpServletRequest("POST", "/oauth2/device_verification");
        request.setRemoteAddr(ADDRESS);
        request.setParameter("user_code", "bcdf ghjk");
        final var client = deviceClient();
        when(authorizationService.findByToken(USER_CODE, DeviceVerificationRequestGuard.USER_CODE_TOKEN_TYPE))
                .thenReturn(OAuth2Authorization.withRegisteredClient(client).principalName(USER)
                        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).build());
        when(registeredClientRepository.findById(REGISTERED_ID)).thenReturn(client);
        when(authorizationManager.clientRequiresMfa(DEVICE_CLIENT_ID)).thenReturn(true);
        when(authorizationManager.evaluate(user, true)).thenReturn(new AuthorizationDecision(false));

        assertThrows(SecondFactorRequiredException.class, () -> guard.convert(request));
    }

    /**
     * Verifies that the stored client wins over the {@code client_id} a consent decision names.
     */
    @Test
    void convert_whenTheConsentNamesAnotherClient_appliesThePolicyOfTheStoredClient() {
        final var user = signIn();
        final var request = request();
        request.setParameter("user_code", USER_CODE);
        final var client = deviceClient();
        when(authorizationService.findByToken(USER_CODE, DeviceVerificationRequestGuard.USER_CODE_TOKEN_TYPE))
                .thenReturn(OAuth2Authorization.withRegisteredClient(client).principalName(USER)
                        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).build());
        when(registeredClientRepository.findById(REGISTERED_ID)).thenReturn(client);
        when(authorizationManager.clientRequiresMfa(DEVICE_CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request));
    }

    /**
     * Verifies that an unknown user code falls back to the {@code client_id} of the request.
     */
    @Test
    void convert_whenNoAuthorizationHoldsTheUserCode_usesTheClientIdParameter() {
        final var user = signIn();
        final var request = request();
        request.setParameter("user_code", USER_CODE);
        when(authorizationService.findByToken(USER_CODE, DeviceVerificationRequestGuard.USER_CODE_TOKEN_TYPE))
                .thenReturn(null);
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(true);
        when(authorizationManager.evaluate(user, true)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request));
    }

    /**
     * Verifies that a value that cannot be a user code is never looked up.
     */
    @Test
    void convert_whenTheUserCodeIsMalformed_doesNotLookItUp() {
        final var user = signIn();
        final var request = request();
        request.setParameter("user_code", "ABC");
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request));

        verify(authorizationService, never()).findByToken(any(), any());
    }

    /**
     * Verifies that a stored authorization whose client was removed falls back to the {@code client_id} parameter.
     */
    @Test
    void convert_whenTheStoredClientNoLongerExists_usesTheClientIdParameter() {
        final var user = signIn();
        final var request = request();
        request.setParameter("user_code", USER_CODE);
        when(authorizationService.findByToken(USER_CODE, DeviceVerificationRequestGuard.USER_CODE_TOKEN_TYPE))
                .thenReturn(OAuth2Authorization.withRegisteredClient(deviceClient()).principalName(USER)
                        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).build());
        when(registeredClientRepository.findById(REGISTERED_ID)).thenReturn(null);
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(true));

        assertNull(guard.convert(request));
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
     * Builds the client of the device authorizations.
     *
     * @return the client.
     */
    private static RegisteredClient deviceClient() {
        return RegisteredClient.withId(REGISTERED_ID).clientId(DEVICE_CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).build();
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

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

package com.irurueta.authserver.authorization.infrastructure.persistence.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Unit tests of {@link ReuseDetectingAuthorizationService}, with the delegate and the JDBC client mocked. The
 * behaviour against PostgreSQL and the JDBC authorization service runs in
 * {@link ReuseDetectingAuthorizationServiceIT}.
 */
@ExtendWith(MockitoExtension.class)
class ReuseDetectingAuthorizationServiceTest {

    /** Principal used by the tests. */
    private static final String PRINCIPAL = "alice";

    /** Lifetime of the refresh tokens used by the tests, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** Length of a hexadecimal SHA-256 digest. */
    private static final int HASH_LENGTH = 64;

    /** Service that stores the authorizations. */
    @Mock
    private OAuth2AuthorizationService delegate;

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Service under test. */
    @InjectMocks
    private ReuseDetectingAuthorizationService service;

    /**
     * Verifies that a new authorization is only saved.
     */
    @Test
    void save_whenAuthorizationIsNew_onlyDelegates() {
        final var authorization = authorization("id-1", token());

        service.save(authorization);

        verify(delegate).save(authorization);
        verifyNoInteractions(client);
    }

    /**
     * Verifies that the hash of the replaced refresh token is recorded.
     */
    @Test
    void save_whenRefreshTokenIsRotated_recordsHashOfOldToken() {
        final var oldToken = token();
        final var previous = authorization("id-2", oldToken);
        final var current = authorization("id-2", token());
        when(delegate.findById("id-2")).thenReturn(previous);

        service.save(current);

        verify(delegate).save(current);
        final var hash = ReuseDetectingAuthorizationService.hash(oldToken.getTokenValue());
        verify(client.sql(any(String.class)).params(hash, "id-2")).update();
    }

    /**
     * Verifies that nothing is recorded when the refresh token is not rotated.
     */
    @Test
    void save_whenRefreshTokenIsUnchanged_doesNotRecord() {
        final var value = token();
        when(delegate.findById("id-3")).thenReturn(authorization("id-3", value));

        service.save(authorization("id-3", value));

        verifyNoInteractions(client);
    }

    /**
     * Verifies that nothing is recorded when the stored authorization has no refresh token.
     */
    @Test
    void save_whenPreviousHasNoRefreshToken_doesNotRecord() {
        when(delegate.findById("id-4")).thenReturn(authorization("id-4", null));

        service.save(authorization("id-4", token()));

        verifyNoInteractions(client);
    }

    /**
     * Verifies that the authorization is removed through the delegate.
     */
    @Test
    void remove_whenCalled_delegates() {
        final var authorization = authorization("id-5", token());

        service.remove(authorization);

        verify(delegate).remove(authorization);
    }

    /**
     * Verifies that the authorization is found through the delegate.
     */
    @Test
    void findById_whenCalled_delegates() {
        final var authorization = authorization("id-6", token());
        when(delegate.findById("id-6")).thenReturn(authorization);

        assertSame(authorization, service.findById("id-6"));
    }

    /**
     * Verifies that a token the delegate knows is resolved without consulting the consumed tokens.
     */
    @Test
    void findByToken_whenDelegateFindsIt_returnsItWithoutQuery() {
        final var value = token();
        final var authorization = authorization("id-7", value);
        when(delegate.findByToken(value.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);

        assertSame(authorization, service.findByToken(value.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));
        verifyNoInteractions(client);
    }

    /**
     * Verifies that an unknown access token is not looked up among the consumed refresh tokens.
     */
    @Test
    void findByToken_whenAccessTokenIsUnknown_returnsNullWithoutQuery() {
        assertNull(service.findByToken(token().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN));

        verifyNoInteractions(client);
    }

    /**
     * Verifies that presenting a rotated-out token revokes its authorization.
     */
    @Test
    void findByToken_whenConsumedTokenIsPresented_revokesAuthorization() {
        final var value = token();
        final var compromised = authorization("id-8", token());
        when(client.sql(any(String.class)).param(ReuseDetectingAuthorizationService.hash(value.getTokenValue()))
                .query(String.class).optional()).thenReturn(Optional.of("id-8"));
        when(delegate.findById("id-8")).thenReturn(compromised);

        assertNull(service.findByToken(value.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));

        verify(delegate).remove(compromised);
    }

    /**
     * Verifies that an unknown token that was never consumed revokes nothing.
     */
    @Test
    void findByToken_whenTokenWasNeverConsumed_revokesNothing() {
        final var value = token();
        when(client.sql(any(String.class)).param(ReuseDetectingAuthorizationService.hash(value.getTokenValue()))
                .query(String.class).optional()).thenReturn(Optional.empty());

        assertNull(service.findByToken(value.getTokenValue(), null));

        verify(delegate, never()).remove(any());
    }

    /**
     * Verifies that the hash is a 64 character hexadecimal digest.
     */
    @Test
    void hash_whenCalled_returnsSha256Hex() {
        assertEquals(HASH_LENGTH, ReuseDetectingAuthorizationService.hash(token().getTokenValue()).length());
    }

    /**
     * Builds a random refresh token value.
     *
     * @return the token.
     */
    private static OAuth2RefreshToken token() {
        final var issuedAt = Instant.parse("2026-01-01T10:00:00Z");
        return new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, issuedAt.plusSeconds(TTL_SECONDS));
    }

    /**
     * Builds an authorization.
     *
     * @param id           identifier of the authorization.
     * @param refreshToken its refresh token, or {@code null}.
     * @return the authorization.
     */
    private static OAuth2Authorization authorization(final String id, final OAuth2RefreshToken refreshToken) {
        final var registered = RegisteredClient.withId("row").clientId("client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        final var builder = OAuth2Authorization.withRegisteredClient(registered).id(id).principalName(PRINCIPAL)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        if (refreshToken != null) {
            builder.refreshToken(refreshToken);
        }
        return builder.build();
    }
}

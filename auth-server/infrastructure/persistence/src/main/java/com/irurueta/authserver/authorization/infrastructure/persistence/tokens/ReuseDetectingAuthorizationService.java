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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * Decorator of an {@link OAuth2AuthorizationService} that detects the reuse of rotated refresh tokens. When saving an
 * authorization whose refresh token changed, the hash of the old token is recorded; when a token that was already
 * rotated out is presented, the authorization it belonged to is revoked, because the token was either stolen or
 * replayed.
 */
@Slf4j
@RequiredArgsConstructor
public class ReuseDetectingAuthorizationService implements OAuth2AuthorizationService {

    /** Algorithm that hashes the stored tokens. */
    private static final String HASH_ALGORITHM = "SHA-256";

    /** Statement recording a rotated-out token. */
    private static final String INSERT_CONSUMED = """
            INSERT INTO consumed_refresh_tokens (token_hash, authorization_id) VALUES (?, ?)
            ON CONFLICT (token_hash) DO NOTHING
            """;

    /** Query returning the authorization a rotated-out token belonged to. */
    private static final String FIND_CONSUMED = """
            SELECT authorization_id FROM consumed_refresh_tokens WHERE token_hash = ?
            """;

    /** Service that stores the authorizations. */
    private final OAuth2AuthorizationService delegate;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    // tag::tokens-reuse-detection[]
    @Override
    public void save(final OAuth2Authorization authorization) {
        final var previous = delegate.findById(authorization.getId());
        delegate.save(authorization);
        if (previous == null) {
            return;
        }
        final var oldToken = refreshTokenValue(previous);
        if (oldToken != null && !oldToken.equals(refreshTokenValue(authorization))) {
            jdbcClient.sql(INSERT_CONSUMED).params(hash(oldToken), authorization.getId()).update();
        }
    }

    @Override
    public void remove(final OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(final String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(final String token, final OAuth2TokenType tokenType) {
        final var authorization = delegate.findByToken(token, tokenType);
        if (authorization != null || (tokenType != null && !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType))) {
            return authorization;
        }
        jdbcClient.sql(FIND_CONSUMED).param(hash(token)).query(String.class).optional()
                .map(delegate::findById)
                .ifPresent(compromised -> {
                    log.warn("A rotated refresh token was presented again; revoking the authorization {}",
                            compromised.getId());
                    delegate.remove(compromised);
                });
        return null;
    }
    // end::tokens-reuse-detection[]

    /**
     * Reads the value of the refresh token of an authorization.
     *
     * @param authorization the authorization.
     * @return the token value, or {@code null} when the authorization has no refresh token.
     */
    private static String refreshTokenValue(final OAuth2Authorization authorization) {
        final var token = authorization.getRefreshToken();
        final OAuth2Token value = token == null ? null : token.getToken();
        return value instanceof OAuth2RefreshToken refreshToken ? refreshToken.getTokenValue() : null;
    }

    /**
     * Hashes a token value, so that the stored values cannot be used as tokens.
     *
     * @param token token value.
     * @return the hexadecimal SHA-256 digest.
     */
    static String hash(final String token) {
        try {
            final var digest = MessageDigest.getInstance(HASH_ALGORITHM);
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " is not available", e);
        }
    }
}

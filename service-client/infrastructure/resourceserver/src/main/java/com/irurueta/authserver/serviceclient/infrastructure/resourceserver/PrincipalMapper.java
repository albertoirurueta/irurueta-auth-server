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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import com.nimbusds.jwt.JWTParser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HexFormat;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;

/**
 * Builds the principals the authorized client manager caches tokens under. There is no security context in the
 * service client, so every call names its principal.
 */
@Component
public class PrincipalMapper {

    /** Key of the principal of the service client itself. */
    private static final String SERVICE_CLIENT_KEY = "service-client";

    /** Bytes of the digest of the subject token kept in the name. */
    private static final int DIGEST_BYTES = 8;

    /**
     * Builds the principal of the service client, which the client credentials token is cached under.
     *
     * @param clientId identifier of the client, used as the name.
     * @return the principal.
     */
    public Authentication serviceClient(final String clientId) {
        return new AnonymousAuthenticationToken(SERVICE_CLIENT_KEY, clientId,
                AuthorityUtils.createAuthorityList("ROLE_SERVICE_CLIENT"));
    }

    /**
     * Builds the principal of a user whose token is exchanged. Its name is the {@code sub} claim of the token when
     * it is a readable JWT, followed by a digest of the whole token: the claim is not verified here (the
     * authorization server does that), so the digest keeps two different tokens from ever sharing a cached
     * exchange.
     *
     * @param subjectToken access token of the user.
     * @return the principal, whose principal object is the token, as the exchange provider expects.
     */
    public Authentication user(final String subjectToken) {
        final var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, subjectToken, null, null);
        return new SubjectTokenAuthentication(token, subjectOf(subjectToken) + "#" + digestOf(subjectToken));
    }

    /**
     * Reads the {@code sub} claim of a JWT without verifying it.
     *
     * @param token the token.
     * @return the claim, or {@code "user"} when the token is opaque or has no subject.
     */
    private static String subjectOf(final String token) {
        try {
            final var subject = JWTParser.parse(token).getJWTClaimsSet().getSubject();
            return subject == null ? "user" : subject;
        } catch (final ParseException e) {
            return "user";
        }
    }

    /**
     * Digests a token.
     *
     * @param token the token.
     * @return the first bytes of its SHA-256 digest, in hexadecimal.
     */
    private static String digestOf(final String token) {
        try {
            final var digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, DIGEST_BYTES);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}

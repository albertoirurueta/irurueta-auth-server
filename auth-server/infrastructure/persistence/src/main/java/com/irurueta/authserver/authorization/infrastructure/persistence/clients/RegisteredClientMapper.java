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

package com.irurueta.authserver.authorization.infrastructure.persistence.clients;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Maps the domain {@link ClientRegistration} onto Spring Authorization Server's {@link RegisteredClient} and back.
 * The audiences, which the framework has no field for, travel as the {@value #AUDIENCES_SETTING} custom client
 * setting.
 */
@Component
public class RegisteredClientMapper {

    /** Name of the custom client setting that holds the audiences of the access tokens issued to the client. */
    public static final String AUDIENCES_SETTING = "settings.client.audiences";

    /**
     * Name of the custom client setting that makes every user of the client complete a second factor. It is only
     * written and read here: everybody else asks {@code ClientRegistration.mfaRequired()} through the client port.
     */
    public static final String MFA_REQUIRED_SETTING = "settings.client.mfa.required";

    /**
     * Name of the custom client setting that holds the client's registered public JWK set as JSON, used to verify
     * {@code private_key_jwt} assertions and self-signed certificates.
     */
    public static final String JWKS_SETTING = "settings.client.jwks";

    /** Authentication method that marks a public client. */
    private static final String AUTH_METHOD_NONE = ClientAuthenticationMethod.NONE.getValue();

    /**
     * Maps a registration to a registered client.
     *
     * @param registration the registration.
     * @param id           internal identifier of the registered client.
     * @param issuedAt     instant the client identifier was issued.
     * @param secret       encoded secret, or {@code null}.
     * @return the registered client.
     * @throws IllegalArgumentException if the token endpoint signing algorithm is not a JWS signature algorithm.
     */
    public RegisteredClient toRegisteredClient(
            final ClientRegistration registration, final String id, final Instant issuedAt, final String secret) {
        final var clientSettings = ClientSettings.builder()
                .requireProofKey(registration.requireProofKey())
                .requireAuthorizationConsent(registration.requireConsent())
                .setting(AUDIENCES_SETTING, new ArrayList<>(registration.audiences()))
                .setting(MFA_REQUIRED_SETTING, registration.mfaRequired());
        // tag::clients-auth-settings[]
        if (registration.jwkSetUrl() != null) {
            clientSettings.jwkSetUrl(registration.jwkSetUrl());
        }
        if (registration.jwks() != null) {
            clientSettings.setting(JWKS_SETTING, registration.jwks());
        }
        if (registration.tokenEndpointSigningAlgorithm() != null) {
            clientSettings.tokenEndpointAuthenticationSigningAlgorithm(
                    signingAlgorithmOf(registration.tokenEndpointSigningAlgorithm()));
        }
        if (registration.tlsClientAuthSubjectDn() != null) {
            clientSettings.x509CertificateSubjectDN(registration.tlsClientAuthSubjectDn());
        }
        // end::clients-auth-settings[]
        final var builder = RegisteredClient.withId(id)
                .clientId(registration.clientId())
                .clientIdIssuedAt(issuedAt)
                .clientSecret(secret)
                .clientName(registration.name())
                .clientAuthenticationMethods(methods -> registration.authMethods()
                        .forEach(method -> methods.add(new ClientAuthenticationMethod(method))))
                .authorizationGrantTypes(types -> registration.grantTypes()
                        .forEach(type -> types.add(new AuthorizationGrantType(type))))
                .redirectUris(uris -> uris.addAll(registration.redirectUris()))
                .postLogoutRedirectUris(uris -> uris.addAll(registration.postLogoutRedirectUris()))
                .scopes(scopes -> scopes.addAll(registration.scopes()))
                .clientSettings(clientSettings.build())
                // tag::tokens-settings[]
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(registration.accessTokenTtl())
                        .refreshTokenTimeToLive(registration.refreshTokenTtl())
                        .accessTokenFormat(new OAuth2TokenFormat(registration.accessTokenFormat()))
                        .reuseRefreshTokens(registration.reuseRefreshTokens())
                        .x509CertificateBoundAccessTokens(registration.certificateBoundAccessTokens())
                        .build());
                // end::tokens-settings[]
        return builder.build();
    }

    /**
     * Maps a registered client to a registration. The framework keeps these collections as sets, so they are
     * returned sorted to make the result deterministic. A client is confidential unless it authenticates with
     * {@code none}.
     *
     * @param client the registered client.
     * @return the registration.
     */
    public ClientRegistration toRegistration(final RegisteredClient client) {
        final var authMethods = client.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue).sorted().toList();
        final var settings = client.getClientSettings();
        final var tokenSettings = client.getTokenSettings();
        return new ClientRegistration(client.getClientId(), client.getClientName(),
                !authMethods.contains(AUTH_METHOD_NONE), authMethods,
                client.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).sorted().toList(),
                client.getRedirectUris().stream().sorted().toList(), client.getScopes().stream().sorted().toList(),
                settings.isRequireProofKey(), audiencesOf(settings), tokenSettings.getAccessTokenTimeToLive(),
                tokenSettings.getRefreshTokenTimeToLive(), tokenSettings.getAccessTokenFormat().getValue(),
                tokenSettings.isReuseRefreshTokens(),
                client.getPostLogoutRedirectUris().stream().sorted().toList(),
                settings.isRequireAuthorizationConsent(), mfaRequiredOf(settings), settings.getJwkSetUrl(),
                jwksOf(settings), signingAlgorithmNameOf(settings), settings.getX509CertificateSubjectDN(),
                tokenSettings.isX509CertificateBoundAccessTokens());
    }

    /**
     * Reads the audiences custom setting.
     *
     * @param settings client settings.
     * @return the audiences; empty when the setting is absent (the registration then defaults to the client id).
     */
    public List<String> audiencesOf(final ClientSettings settings) {
        final var value = settings.getSetting(AUDIENCES_SETTING);
        if (value instanceof List<?> audiences) {
            return audiences.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    /**
     * Reads the second-factor custom setting.
     *
     * @param settings client settings.
     * @return {@code true} only when the setting is present and true.
     */
    public boolean mfaRequiredOf(final ClientSettings settings) {
        return Boolean.TRUE.equals(settings.getSetting(MFA_REQUIRED_SETTING));
    }

    /**
     * Reads the registered JWK set custom setting.
     *
     * @param settings client settings.
     * @return the JWK set JSON, or {@code null} when the setting is absent.
     */
    public String jwksOf(final ClientSettings settings) {
        final var value = settings.getSetting(JWKS_SETTING);
        return value instanceof String jwks && StringUtils.hasText(jwks) ? jwks : null;
    }

    /**
     * Reads the token endpoint authentication signing algorithm.
     *
     * @param settings client settings.
     * @return the algorithm name, or {@code null} when none is set.
     */
    private String signingAlgorithmNameOf(final ClientSettings settings) {
        final JwsAlgorithm algorithm = settings.getTokenEndpointAuthenticationSigningAlgorithm();
        return algorithm == null ? null : algorithm.getName();
    }

    /**
     * Resolves a JWS signature algorithm by name.
     *
     * @param name the algorithm name, for example {@code RS256}.
     * @return the algorithm.
     * @throws IllegalArgumentException if the name is not a JWS signature algorithm.
     */
    private SignatureAlgorithm signingAlgorithmOf(final String name) {
        final var algorithm = SignatureAlgorithm.from(name);
        if (algorithm == null) {
            throw new IllegalArgumentException("unsupported token endpoint signing algorithm: " + name);
        }
        return algorithm;
    }
}

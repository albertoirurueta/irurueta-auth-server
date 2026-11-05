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
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link ClientRegistrationRepository} over Spring Authorization Server's {@link RegisteredClientRepository}
 * (the JDBC one), which reads and writes the {@code oauth2_registered_client} table. The operations that
 * repository does not offer (listing, deleting, replacing a secret) run directly on that table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcClientRegistrationRepository implements ClientRegistrationRepository {

    /** Name of the custom client setting that holds the audiences of the access tokens issued to the client. */
    public static final String AUDIENCES_SETTING = "settings.client.audiences";

    /** Sub-query selecting the internal id of a client by its client id. */
    private static final String CLIENT_ROW_ID = "(SELECT id FROM oauth2_registered_client WHERE client_id = ?)";

    /** Statement deleting the authorizations of a client. */
    private static final String DELETE_AUTHORIZATIONS =
            "DELETE FROM oauth2_authorization WHERE registered_client_id = " + CLIENT_ROW_ID;

    /** Statement deleting the consents granted to a client. */
    private static final String DELETE_CONSENTS =
            "DELETE FROM oauth2_authorization_consent WHERE registered_client_id = " + CLIENT_ROW_ID;

    /** Authentication method that marks a public client. */
    private static final String AUTH_METHOD_NONE = ClientAuthenticationMethod.NONE.getValue();

    /** Repository that maps registered clients to rows. */
    private final RegisteredClientRepository registeredClientRepository;

    /** JDBC client used for the operations the registered client repository lacks. */
    private final JdbcClient jdbcClient;

    @Override
    public Optional<ClientRegistration> findByClientId(final String clientId) {
        return Optional.ofNullable(registeredClientRepository.findByClientId(clientId))
                .map(JdbcClientRegistrationRepository::toRegistration);
    }

    @Override
    public List<ClientRegistration> findAll() {
        return jdbcClient.sql("SELECT client_id FROM oauth2_registered_client ORDER BY client_id")
                .query(String.class).list().stream()
                .map(registeredClientRepository::findByClientId)
                .filter(Objects::nonNull)
                .map(JdbcClientRegistrationRepository::toRegistration)
                .toList();
    }

    @Override
    public void save(final ClientRegistration registration, final String encodedSecret) {
        final var existing = registeredClientRepository.findByClientId(registration.clientId());
        final var id = existing == null ? UUID.randomUUID().toString() : existing.getId();
        final var issuedAt = existing == null || existing.getClientIdIssuedAt() == null
                ? Instant.now() : existing.getClientIdIssuedAt();
        final var secret = encodedSecret == null && existing != null ? existing.getClientSecret() : encodedSecret;
        registeredClientRepository.save(toRegisteredClient(registration, id, issuedAt, secret));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The authorizations (with their consumed refresh tokens, by cascade) and the consents granted to the client
     * reference it by its internal id without a foreign key, so they are deleted first, in the same transaction:
     * otherwise loading one of them later fails because its client is gone.
     */
    @Override
    @Transactional
    public void deleteByClientId(final String clientId) {
        jdbcClient.sql(DELETE_AUTHORIZATIONS).param(clientId).update();
        jdbcClient.sql(DELETE_CONSENTS).param(clientId).update();
        jdbcClient.sql("DELETE FROM oauth2_registered_client WHERE client_id = ?").param(clientId).update();
    }

    @Override
    public void updateSecret(final String clientId, final String encodedSecret) {
        jdbcClient.sql("UPDATE oauth2_registered_client SET client_secret = ? WHERE client_id = ?")
                .params(encodedSecret, clientId).update();
    }

    /**
     * Maps a registration to a registered client.
     *
     * @param registration the registration.
     * @param id           internal identifier of the registered client.
     * @param issuedAt     instant the client identifier was issued.
     * @param secret       encoded secret, or {@code null}.
     * @return the registered client.
     */
    private static RegisteredClient toRegisteredClient(
            final ClientRegistration registration, final String id, final Instant issuedAt, final String secret) {
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
                .scopes(scopes -> scopes.addAll(registration.scopes()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(registration.requireProofKey())
                        .requireAuthorizationConsent(false)
                        .setting(AUDIENCES_SETTING, new ArrayList<>(registration.audiences()))
                        .build())
                // tag::tokens-settings[]
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(registration.accessTokenTtl())
                        .refreshTokenTimeToLive(registration.refreshTokenTtl())
                        .accessTokenFormat(new OAuth2TokenFormat(registration.accessTokenFormat()))
                        .reuseRefreshTokens(registration.reuseRefreshTokens())
                        .build());
                // end::tokens-settings[]
        return builder.build();
    }

    /**
     * Maps a registered client to a registration. The framework keeps these collections as sets, so they are
     * returned sorted to make the result deterministic.
     *
     * @param client the registered client.
     * @return the registration.
     */
    private static ClientRegistration toRegistration(final RegisteredClient client) {
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
                tokenSettings.isReuseRefreshTokens());
    }

    /**
     * Reads the audiences custom setting.
     *
     * @param settings client settings.
     * @return the audiences; empty when the setting is absent (the registration then defaults to the client id).
     */
    private static List<String> audiencesOf(final ClientSettings settings) {
        final var value = settings.getSetting(AUDIENCES_SETTING);
        if (value instanceof List<?> audiences) {
            return audiences.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}

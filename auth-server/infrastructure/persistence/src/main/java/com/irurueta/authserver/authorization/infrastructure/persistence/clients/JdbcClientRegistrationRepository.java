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
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;

/**
 * {@link ClientRegistrationRepository} over Spring Authorization Server's {@link RegisteredClientRepository}
 * (the JDBC one), which reads and writes the {@code oauth2_registered_client} table. The operations that
 * repository does not offer (listing, deleting, replacing a secret) run directly on that table. The conversion
 * between both models belongs to the {@link RegisteredClientMapper}.
 */
@Repository
@RequiredArgsConstructor
public class JdbcClientRegistrationRepository implements ClientRegistrationRepository {

    /** Sub-query selecting the internal id of a client by its client id. */
    private static final String CLIENT_ROW_ID = "(SELECT id FROM oauth2_registered_client WHERE client_id = ?)";

    /** Statement deleting the authorizations of a client. */
    private static final String DELETE_AUTHORIZATIONS =
            "DELETE FROM oauth2_authorization WHERE registered_client_id = " + CLIENT_ROW_ID;

    /** Statement deleting the consents granted to a client. */
    private static final String DELETE_CONSENTS =
            "DELETE FROM oauth2_authorization_consent WHERE registered_client_id = " + CLIENT_ROW_ID;

    /** Repository that maps registered clients to rows. */
    private final RegisteredClientRepository registeredClientRepository;

    /** JDBC client used for the operations the registered client repository lacks. */
    private final JdbcClient jdbcClient;

    /** Maps between registrations and registered clients. */
    private final RegisteredClientMapper registeredClientMapper;

    @Override
    public Optional<ClientRegistration> findByClientId(final String clientId) {
        return Optional.ofNullable(registeredClientRepository.findByClientId(clientId))
                .map(registeredClientMapper::toRegistration);
    }

    @Override
    public List<ClientRegistration> findAll() {
        return jdbcClient.sql("SELECT client_id FROM oauth2_registered_client ORDER BY client_id")
                .query(String.class).list().stream()
                .map(registeredClientRepository::findByClientId)
                .filter(Objects::nonNull)
                .map(registeredClientMapper::toRegistration)
                .toList();
    }

    @Override
    public void save(final ClientRegistration registration, final String encodedSecret) {
        final var existing = registeredClientRepository.findByClientId(registration.clientId());
        final var id = existing == null ? UUID.randomUUID().toString() : existing.getId();
        final var issuedAt = existing == null || existing.getClientIdIssuedAt() == null
                ? Instant.now() : existing.getClientIdIssuedAt();
        final var secret = encodedSecret == null && existing != null ? existing.getClientSecret() : encodedSecret;
        registeredClientRepository.save(registeredClientMapper.toRegisteredClient(registration, id, issuedAt, secret));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The authorizations (with their consumed refresh tokens, by cascade) and the consents granted to the client
     * reference it by its internal id without a foreign key, so they are deleted first, in the same transaction:
     * otherwise loading one of them later fails because its client is gone. The transaction is the caller's: use
     * cases demarcate transactions, never the adapters.
     */
    @Override
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
}

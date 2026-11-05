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

package com.irurueta.authserver.authorization.application.clients;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Use case that registers the configured clients (built from {@link DefaultClientDefinitions}) that are missing. It
 * is idempotent: a client that already exists is left untouched, including its secret.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class SeedRegisteredClientsUseCase {

    /** Port that stores the clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /** Port that encodes secrets. */
    private final PasswordHasher passwordHasher;

    /**
     * Registers the missing clients among the given definitions.
     *
     * @param definitions   the clients this deployment seeds; a client that is not configured is not in the list.
     * @param clientSecrets clear-text secrets by client id, taken from the environment; only needed for the
     *                      confidential clients that do not exist yet.
     * @return the ids of the clients that were created and of those skipped; a confidential client without a
     * secret is skipped and does not prevent the other clients from being created.
     */
    public SeedResult execute(final List<ClientRegistration> definitions, final Map<String, String> clientSecrets) {
        final var created = new ArrayList<String>();
        final var skipped = new ArrayList<String>();
        for (final var definition : definitions) {
            if (clientRegistrationRepository.findByClientId(definition.clientId()).isPresent()) {
                continue;
            }
            String encodedSecret = null;
            if (definition.confidential()) {
                final var secret = clientSecrets.get(definition.clientId());
                if (!StringUtils.hasText(secret)) {
                    skipped.add(definition.clientId());
                    continue;
                }
                encodedSecret = passwordHasher.encode(secret);
            }
            clientRegistrationRepository.save(definition, encodedSecret);
            created.add(definition.clientId());
        }
        return new SeedResult(created, skipped);
    }
}

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

package com.irurueta.authserver.authorization.infrastructure.persistence.keys;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.keys.SignedTokenLifetimes;
import java.time.Duration;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * {@link SignedTokenLifetimes} over the registered clients: the longest of the ID-token lifetime and the access-token
 * lifetimes of the clients that receive self-contained (signed) access tokens. Reference access tokens are opaque and
 * never signed, so they do not count.
 */
@Component
@RequiredArgsConstructor
public class RegisteredClientTokenLifetimes implements SignedTokenLifetimes {

    /**
     * Lifetime of an ID token. Spring Authorization Server's {@code JwtGenerator} fixes it at 30 minutes whatever the
     * client settings say, so it is a fact of the framework rather than a setting.
     */
    static final Duration ID_TOKEN_TTL = Duration.ofMinutes(30);

    /** Port that stores the registered clients. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public Duration longest() {
        final var accessTokens = clientRegistrationRepository.findAll().stream()
                .filter(client -> ClientRegistration.FORMAT_SELF_CONTAINED.equals(client.accessTokenFormat()))
                .map(ClientRegistration::accessTokenTtl);
        return Stream.concat(Stream.of(ID_TOKEN_TTL), accessTokens).max(Duration::compareTo).orElseThrow();
    }
}

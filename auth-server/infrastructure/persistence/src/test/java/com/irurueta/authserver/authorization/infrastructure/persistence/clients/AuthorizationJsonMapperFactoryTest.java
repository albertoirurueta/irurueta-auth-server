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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Unit tests of {@link AuthorizationJsonMapperFactory}.
 */
class AuthorizationJsonMapperFactoryTest {

    /** Epoch second used as a numeric claim. */
    private static final long EPOCH_SECOND = 1_767_261_600L;

    /** Factory under test. */
    private final AuthorizationJsonMapperFactory factory = new AuthorizationJsonMapperFactory();

    /**
     * Verifies that a map holding a long survives a round trip with default typing.
     */
    @Test
    void create_whenMapHoldsALong_roundTripsIt() {
        final JsonMapper mapper = factory.create();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var claims = new HashMap<String, Object>();
        claims.put("auth_time", EPOCH_SECOND);
        final var json = mapper.writerFor(type).writeValueAsString(claims);
        final var read = mapper.readValue(json, type);
        assertEquals(EPOCH_SECOND, ((Number) read.get("auth_time")).longValue());
    }

    /**
     * Verifies that the principal of an authorization started with a passkey, a {@code WebAuthnAuthentication} that
     * holds a user entity, survives a round trip, with the factor authority it carries.
     */
    @Test
    void create_whenMapHoldsAPasskeyAuthentication_roundTripsIt() {
        final JsonMapper mapper = factory.create();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var entity = ImmutablePublicKeyCredentialUserEntity.builder().name("alice").id(Bytes.random())
                .displayName("alice").build();
        final var authentication = new WebAuthnAuthentication(entity,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY)));
        final var attributes = new HashMap<String, Object>();
        attributes.put("principal", authentication);

        final var json = mapper.writerFor(type).writeValueAsString(attributes);
        final var read = mapper.readValue(json, type);

        final var principal = assertInstanceOf(WebAuthnAuthentication.class, read.get("principal"));
        assertEquals("alice", principal.getName());
        assertEquals(entity.getId(), principal.getPrincipal().getId());
        assertEquals(List.of(FactorGrantedAuthority.WEBAUTHN_AUTHORITY),
                principal.getAuthorities().stream().map(authority -> authority.getAuthority()).toList());
    }
}

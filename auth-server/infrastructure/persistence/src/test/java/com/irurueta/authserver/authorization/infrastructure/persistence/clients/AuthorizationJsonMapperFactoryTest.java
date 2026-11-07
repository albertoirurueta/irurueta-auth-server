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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Unit tests of {@link AuthorizationJsonMapperFactory}.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationJsonMapperFactoryTest {

    /** Epoch second used as a numeric claim. */
    private static final long EPOCH_SECOND = 1_767_261_600L;

    /** Name of the attribute holding the principal. */
    private static final String PRINCIPAL = "principal";

    /** Contributor of a module, mocked so the tests control what it adds. */
    @Mock
    private AuthorizationJacksonModuleContributor contributor;

    /**
     * Verifies that a map holding a long survives a round trip with default typing, without any contributor.
     */
    @Test
    void create_whenMapHoldsALong_roundTripsIt() {
        final var mapper = new AuthorizationJsonMapperFactory(List.<AuthorizationJacksonModuleContributor>of())
                .create();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var claims = new HashMap<String, Object>();
        claims.put("auth_time", EPOCH_SECOND);
        final var json = mapper.writerFor(type).writeValueAsString(claims);
        final var read = mapper.readValue(json, type);
        assertEquals(EPOCH_SECOND, ((Number) read.get("auth_time")).longValue());
    }

    /**
     * Verifies that the module of a contributor is added and that the types it allowed in the validator, which the
     * framework's modules do not allow, are read back: the contributor is called before the validator is used. The
     * principal of an authorization started with a passkey is the example.
     */
    @Test
    void create_whenContributorAllowsATypeInTheValidator_readsItBack() {
        stubTheWebauthnModule();
        final var attributes = attributesWithAPasskeyPrincipal();
        final var type = new TypeReference<Map<String, Object>>() { };

        final var mapper = new AuthorizationJsonMapperFactory(List.of(contributor)).create();
        final var read = mapper.readValue(mapper.writerFor(type).writeValueAsString(attributes), type);

        final var principal = assertInstanceOf(WebAuthnAuthentication.class, read.get(PRINCIPAL));
        final var expected = (WebAuthnAuthentication) attributes.get(PRINCIPAL);
        assertEquals("alice", principal.getName());
        assertEquals(expected.getPrincipal().getId(), principal.getPrincipal().getId());
        assertEquals(List.of(FactorGrantedAuthority.WEBAUTHN_AUTHORITY),
                principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /**
     * Verifies that, without the contributor, the same type is refused when it is read back, so the contributed
     * module is what makes the difference.
     */
    @Test
    void create_whenNoContributorAllowsTheType_refusesToReadItBack() {
        stubTheWebauthnModule();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var json = new AuthorizationJsonMapperFactory(List.of(contributor)).create().writerFor(type)
                .writeValueAsString(attributesWithAPasskeyPrincipal());
        final var without = new AuthorizationJsonMapperFactory(List.<AuthorizationJacksonModuleContributor>of())
                .create();

        assertThrows(JacksonException.class, () -> without.readValue(json, type));
    }

    /**
     * Makes the mocked contributor answer the module of the passkeys, configured with the validator it is given.
     */
    private void stubTheWebauthnModule() {
        when(contributor.module(any(BasicPolymorphicTypeValidator.Builder.class))).thenAnswer(invocation -> {
            final var module = new WebauthnJacksonModule();
            module.configurePolymorphicTypeValidator(invocation.getArgument(0));
            return module;
        });
    }

    /**
     * Builds stored attributes whose principal is a passkey authentication holding a user entity.
     *
     * @return the attributes.
     */
    private static Map<String, Object> attributesWithAPasskeyPrincipal() {
        final var entity = ImmutablePublicKeyCredentialUserEntity.builder().name("alice").id(Bytes.random())
                .displayName("alice").build();
        final var attributes = new HashMap<String, Object>();
        attributes.put(PRINCIPAL, new WebAuthnAuthentication(entity,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY))));
        return attributes;
    }
}

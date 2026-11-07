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
package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Unit tests of {@link WebauthnJacksonModuleContributor}.
 */
class WebauthnJacksonModuleContributorTest {

    /** Name of the attribute holding the principal. */
    private static final String PRINCIPAL = "principal";

    /** Contributor under test. */
    private final WebauthnJacksonModuleContributor contributor = new WebauthnJacksonModuleContributor();

    /**
     * Verifies that the module of the passkeys is returned and that, once it has configured the validator the
     * framework's modules are then created with, the principal of an authorization started with a passkey survives
     * a round trip with the factor authority it carries.
     */
    @Test
    void module_whenCalled_returnsTheWebauthnModuleAndAllowsItsTypes() {
        final var validator = BasicPolymorphicTypeValidator.builder();

        final var module = contributor.module(validator);

        assertInstanceOf(WebauthnJacksonModule.class, module);
        final var mapper = JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(), validator))
                .addModule(module)
                .build();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var entity = ImmutablePublicKeyCredentialUserEntity.builder().name("alice").id(Bytes.random())
                .displayName("alice").build();
        final var attributes = new HashMap<String, Object>();
        attributes.put(PRINCIPAL, new WebAuthnAuthentication(entity,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY))));

        final var read = mapper.readValue(mapper.writerFor(type).writeValueAsString(attributes), type);

        final var principal = assertInstanceOf(WebAuthnAuthentication.class, read.get(PRINCIPAL));
        assertEquals("alice", principal.getName());
        assertEquals(entity.getId(), principal.getPrincipal().getId());
    }
}

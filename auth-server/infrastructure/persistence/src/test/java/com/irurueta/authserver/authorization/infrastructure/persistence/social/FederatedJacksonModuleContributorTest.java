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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Unit tests of {@link FederatedJacksonModuleContributor}.
 */
class FederatedJacksonModuleContributorTest {

    /** Name of the attribute holding the principal. */
    private static final String PRINCIPAL = "principal";

    /** Registration id of the provider. */
    private static final String REGISTRATION_ID = "github";

    /** Contributor under test. */
    private final FederatedJacksonModuleContributor contributor = new FederatedJacksonModuleContributor();

    /**
     * Verifies that the module of the OAuth 2.0 client is returned and that, once it has configured the validator
     * the framework's modules are then created with, an authentication started with an OAuth 2.0 user survives a
     * round trip with its authorities and attributes.
     */
    @Test
    void module_whenCalled_returnsTheClientModuleAndAllowsAnOAuth2UserRoundTrip() {
        final var validator = BasicPolymorphicTypeValidator.builder();

        final var module = contributor.module(validator);

        assertInstanceOf(OAuth2ClientJacksonModule.class, module);
        final var mapper = mapper(validator, module);
        final var user = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        FactorGrantedAuthority.fromAuthority("FACTOR_FEDERATED")),
                Map.of("id", "42", "login", "alice"), "id");
        final var read = roundTrip(mapper,
                new OAuth2AuthenticationToken(user, user.getAuthorities(), REGISTRATION_ID));

        final var token = assertInstanceOf(OAuth2AuthenticationToken.class, read);
        assertEquals(REGISTRATION_ID, token.getAuthorizedClientRegistrationId());
        assertEquals("42", token.getName());
        assertEquals("alice", assertInstanceOf(DefaultOAuth2User.class, token.getPrincipal())
                .getAttributes().get("login"));
        assertEquals(2, token.getAuthorities().size());
    }

    /**
     * Verifies that an authentication started with an OpenID Connect user, with its ID token, survives a round trip.
     * The claim values are mutable lists (as parsed JSON gives them): the framework's validator denies the immutable
     * lists of {@code List.of}, which a federated user service must therefore not put in the claims it builds.
     */
    @Test
    void module_whenCalled_allowsAnOidcUserRoundTrip() {
        final var validator = BasicPolymorphicTypeValidator.builder();
        final var mapper = mapper(validator, contributor.module(validator));
        final var issuedAt = Instant.parse("2026-01-01T10:00:00Z");
        final var idToken = new OidcIdToken("token-value", issuedAt, issuedAt.plusSeconds(60),
                Map.of("sub", "local-id", "iss", "https://accounts.example.com", "amr", new ArrayList<>(List.of("pwd", "mfa"))));
        final var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);

        final var read = roundTrip(mapper, new OAuth2AuthenticationToken(user, user.getAuthorities(), "google"));

        final var token = assertInstanceOf(OAuth2AuthenticationToken.class, read);
        final var principal = assertInstanceOf(DefaultOidcUser.class, token.getPrincipal());
        assertEquals("local-id", principal.getName());
        assertEquals(List.of("pwd", "mfa"), principal.getIdToken().getClaims().get("amr"));
    }

    /**
     * Builds the mapper the stored authorizations use, with the module under test added last.
     *
     * @param validator builder of the polymorphic type validator.
     * @param module    module to add.
     * @return the mapper.
     */
    private JsonMapper mapper(final BasicPolymorphicTypeValidator.Builder validator,
                              final JacksonModule module) {
        return JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(), validator))
                .addModule(module)
                .build();
    }

    /**
     * Writes and reads back a principal held in an attribute map, as the authorization service stores it.
     *
     * @param mapper    mapper of the stored authorizations.
     * @param principal object to round trip.
     * @return the object read back.
     */
    private Object roundTrip(final JsonMapper mapper, final Object principal) {
        final var type = new TypeReference<Map<String, Object>>() { };
        final var attributes = new HashMap<String, Object>();
        attributes.put(PRINCIPAL, principal);
        return mapper.readValue(mapper.writerFor(type).writeValueAsString(attributes), type).get(PRINCIPAL);
    }
}

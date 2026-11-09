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
package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import com.nimbusds.jose.JWSObject;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;

/**
 * Checks the published key set in each state of the signing-key lifecycle, that a token signed before a rotation
 * stays valid until its key is removed, and that the administration endpoints need the {@code admin} scope.
 * Lifecycle transitions that depend on elapsed time are provoked by back-dating the key rows, so no test waits.
 */
@PostgresIT(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class KeyRotationIT {

    /** Path of the published key set. */
    private static final String JWKS_PATH = "/oauth2/jwks";

    /** Path of the key administration endpoints. */
    private static final String KEYS_PATH = "/api/admin/keys";

    /** Path of the rotation endpoint. */
    private static final String ROTATE_PATH = KEYS_PATH + "/rotate";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that back-dates the keys and reads their state. */
    @Autowired
    private JdbcClient jdbcClient;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Port the application listens on. */
    @LocalServerPort
    private int port;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that the key set holds the active key and the next one (and only keys that are stored), and no
     * private part.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void jwks_whenStarted_publishesTheActiveAndNextKeysWithoutPrivateParts() throws Exception {
        final var body = mockMvc.perform(get(JWKS_PATH)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        final var published = kids(AuthServerFixtures.parse(body).get("keys"));
        // other tests of this class may have left a retired key behind, still within its retention
        assertTrue(published.containsAll(kidsWithStatus("ACTIVE", "NEXT")));
        assertTrue(kidsWithStatus("ACTIVE", "NEXT", "RETIRED").containsAll(published));
        assertEquals(1, kidsWithStatus("ACTIVE").size());
        assertEquals(1, kidsWithStatus("NEXT").size());
        assertFalse(body.contains("\"d\""), "private exponent is never published");
    }

    // tag::keys-rotation-it[]
    /**
     * Verifies that a token signed before a rotation validates while its key is retired and published, and stops
     * validating once the key is removed, and that new tokens are signed with the new active key.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void rotate_whenKeyIsRetiredThenRemoved_oldTokensValidateUntilRemoval() throws Exception {
        final var admin = fixtures.adminToken();
        final var oldToken = fixtures.adminToken();
        final var oldKid = kidOf(oldToken);
        assertEquals(kidsWithStatus("ACTIVE"), Set.of(oldKid));
        final var nextKid = kidsWithStatus("NEXT").iterator().next();

        // 1. the administrator forces a rotation of a key that is not due: it is retired, the next key is promoted
        // and a new next key is generated
        rotate(admin);

        assertEquals(Set.of(oldKid), kidsWithStatus("RETIRED"));
        assertEquals(Set.of(nextKid), kidsWithStatus("ACTIVE"));
        assertEquals(1, kidsWithStatus("NEXT").size());
        assertTrue(publishedKids().containsAll(kidsWithStatus("RETIRED", "ACTIVE", "NEXT")));
        assertEquals(nextKid, kidOf(fixtures.adminToken()), "new tokens use the new active key");
        decode(oldToken);

        // 2. the old key outlives the effective retention (at least the 24 hours of the e-mail verification tokens
        // it may have signed): the next rotation removes it, and retires the key that was promoted in step 1
        jdbcClient.sql("UPDATE signing_keys SET retired_at = now() - interval '2 days' WHERE kid = ?")
                .param(oldKid).update();
        rotate(admin);

        assertEquals(Set.of(nextKid), kidsWithStatus("RETIRED"));
        assertFalse(publishedKids().contains(oldKid));
        assertTrue(publishedKids().contains(nextKid), "a freshly retired key stays published");
        assertThrows(BadJwtException.class, () -> decode(oldToken));
    }
    // end::keys-rotation-it[]

    /**
     * Verifies that a retired key stays published for longer than the configured two-hour retention, because the
     * e-mail verification tokens it signed live for a day: the effective retention covers the longest signed token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void rotate_whenKeyWasRetiredLongerThanTheConfiguredRetention_keepsItWhileItsTokensMayLive() throws Exception {
        final var admin = fixtures.adminToken();
        final var activeKid = kidsWithStatus("ACTIVE").iterator().next();
        rotate(admin);
        jdbcClient.sql("UPDATE signing_keys SET retired_at = now() - interval '3 hours' WHERE kid = ?")
                .param(activeKid).update();

        rotate(admin);

        assertTrue(kidsWithStatus("RETIRED").contains(activeKid));
        assertTrue(publishedKids().contains(activeKid));
    }

    /**
     * Verifies that the key list never exposes private key material.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void list_whenAdmin_returnsKeysWithoutPrivateMaterial() throws Exception {
        final var body = mockMvc.perform(get(KEYS_PATH).header(AuthServerFixtures.AUTHORIZATION,
                        "Bearer " + fixtures.adminToken()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        final var keys = AuthServerFixtures.parse(body);
        assertTrue(keys.size() >= 2);
        assertFalse(body.contains("\"d\""));
        assertFalse(body.toLowerCase(Locale.ROOT).contains("private"));
    }

    /**
     * Verifies that the administration endpoints reject a missing token and a token without the admin scope, and
     * accept one with it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminEndpoints_whenCallerLacksTheAdminScope_areRejected() throws Exception {
        final var reader = fixtures.clientCredentialsToken(fixtures.createClient(
                List.of("client_credentials"), List.of("read"), List.of("auth-server")), "read");

        mockMvc.perform(get(KEYS_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(ROTATE_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(get(KEYS_PATH).header(AuthServerFixtures.AUTHORIZATION, "Bearer " + reader))
                .andExpect(status().isForbidden())
                .andExpect(header().string("WWW-Authenticate", containsString("insufficient")));
        mockMvc.perform(post(ROTATE_PATH).header(AuthServerFixtures.AUTHORIZATION, "Bearer " + reader))
                .andExpect(status().isForbidden());
    }

    /**
     * Rotates the keys through the administration endpoint.
     *
     * @param admin access token with the admin scope.
     * @throws Exception if the request cannot be performed.
     */
    private void rotate(final String admin) throws Exception {
        mockMvc.perform(post(ROTATE_PATH).header(AuthServerFixtures.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isOk());
    }

    /**
     * Validates a token against the published key set, reading the set afresh.
     *
     * @param token the token.
     */
    private void decode(final String token) {
        NimbusJwtDecoder.withJwkSetUri("http://localhost:" + port + JWKS_PATH).build().decode(token);
    }

    /**
     * Reads the identifiers of the keys currently published.
     *
     * @return the identifiers.
     * @throws Exception if the request cannot be performed.
     */
    private Set<String> publishedKids() throws Exception {
        final var body = mockMvc.perform(get(JWKS_PATH)).andReturn().getResponse().getContentAsString();
        return kids(AuthServerFixtures.parse(body).get("keys"));
    }

    /**
     * Reads the key identifiers of a key array.
     *
     * @param keys the array.
     * @return the identifiers.
     */
    private static Set<String> kids(final JsonNode keys) {
        final var kids = new HashSet<String>();
        keys.forEach(key -> kids.add(key.get("kid").asString()));
        return kids;
    }

    /**
     * Reads the key identifier from the header of a token.
     *
     * @param token the token.
     * @return the identifier.
     * @throws ParseException if the token is malformed.
     */
    private static String kidOf(final String token) throws ParseException {
        return JWSObject.parse(token).getHeader().getKeyID();
    }

    /**
     * Reads the identifiers of the stored keys that have one of the given statuses.
     *
     * @param statuses the statuses.
     * @return the identifiers.
     */
    private Set<String> kidsWithStatus(final String... statuses) {
        return new HashSet<>(jdbcClient.sql("SELECT kid FROM signing_keys WHERE status = ANY (?)")
                .param(statuses).query(String.class).list());
    }
}

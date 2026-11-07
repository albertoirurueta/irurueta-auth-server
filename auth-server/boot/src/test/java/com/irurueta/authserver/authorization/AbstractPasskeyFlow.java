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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import lombok.AccessLevel;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Shared set-up of the passkey integration tests: the paths of the WebAuthn endpoints, the seeding of passkeys
 * straight into the tables Spring Security's repositories use (a real attestation needs an authenticator, which the
 * end-to-end tests have), and the posts a browser script would make.
 */
abstract class AbstractPasskeyFlow extends AbstractMfaFlow {

    /** Path that answers the options of an authentication ceremony. */
    static final String AUTHENTICATION_OPTIONS = "/webauthn/authenticate/options";

    /** Path that verifies an authentication ceremony. */
    static final String AUTHENTICATION = "/login/webauthn";

    /** Path that answers the options of a registration ceremony. */
    static final String REGISTRATION_OPTIONS = "/webauthn/register/options";

    /** Path that verifies a registration ceremony. */
    static final String REGISTRATION = "/webauthn/register";

    /** Path of the account page. */
    static final String ACCOUNT_PAGE = "/account/passkeys";

    /** Name of the claim with the roles. */
    static final String ROLES = "roles";

    /** Name of the claim with the tenant. */
    static final String TENANT = "tenant";

    /** Name of the claim with the audiences. */
    static final String AUD = "aud";

    /** A syntactically valid assertion, as the page script would post it (its signature is never checked here). */
    static final String ASSERTION = """
            {"id":"AQID","rawId":"AQID","response":{"authenticatorData":"AQID","clientDataJSON":"AQID",
            "signature":"AQID","userHandle":"AQID"},"type":"public-key","clientExtensionResults":{},
            "authenticatorAttachment":"platform"}""";

    /** Signature counter of the seeded passkeys. */
    private static final long SEEDED_COUNTER = 1L;

    /** Number of random bytes of a seeded credential identifier or user handle. */
    private static final int HANDLE_BYTES = 16;

    /** Source of the random identifiers. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** JDBC client connected to the database of the application. */
    @Autowired
    @Getter(AccessLevel.PROTECTED)
    private JdbcClient jdbc;

    /**
     * Gives a user a passkey, creating the user entity the framework would create when the passkey was registered.
     *
     * @param username name of the user, also the name of the user entity.
     * @param label    label of the passkey.
     * @return the identifiers of the passkey.
     */
    protected SeededPasskey seedPasskey(final String username, final String label) {
        final var handle = jdbc.sql("SELECT id FROM user_entities WHERE name = ?").param(username)
                .query(String.class).optional().orElseGet(() -> {
                    final var created = randomIdentifier();
                    jdbc.sql("INSERT INTO user_entities (id, name, display_name) VALUES (?, ?, ?)")
                            .params(created, username, username).update();
                    return created;
                });
        final var credentialId = randomIdentifier();
        final var now = Timestamp.from(Instant.now());
        jdbc.sql("""
                INSERT INTO user_credentials (credential_id, user_entity_user_id, public_key, signature_count,
                    uv_initialized, backup_eligible, backup_state, authenticator_transports, created, last_used, label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
                .params(credentialId, handle, "public-key".getBytes(StandardCharsets.UTF_8), SEEDED_COUNTER, true,
                        false, false, "internal", now, now, label).update();
        return new SeededPasskey(handle, credentialId);
    }

    /**
     * Signs a user with an enrolled authenticator app in with the password and completes the second factor, leaving
     * a browser session that satisfies the multi-factor policy.
     *
     * @param enrolled the user, with its enrolled authenticator app.
     * @return the browser session.
     * @throws Exception if a request cannot be performed.
     */
    protected MockHttpSession signInCompletingTheSecondFactor(final AuthServerFixtures.EnrolledUser enrolled)
            throws Exception {
        final var session = signInWithThePasswordOnly(enrolled.user());
        assertAccepted(postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false));
        return session;
    }

    /**
     * Signs a user in with the password only, as the browser does when an authorization request interrupted by the
     * sign-in page is resumed, leaving the session at the second-factor page.
     *
     * @param user the user.
     * @return the browser session, which has presented the password only.
     * @throws Exception if a request cannot be performed.
     */
    protected MockHttpSession signInWithThePasswordOnly(final AuthServerFixtures.TestUser user) throws Exception {
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, newVerifier(), Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        return session;
    }

    /**
     * Counts the passkeys stored for a credential identifier.
     *
     * @param credentialId identifier of the credential.
     * @return the number of rows, zero or one.
     */
    protected long countCredentials(final String credentialId) {
        return jdbc.sql("SELECT count(*) FROM user_credentials WHERE credential_id = ?").param(credentialId)
                .query(Long.class).single();
    }

    /**
     * Counts the security events of a type.
     *
     * @param type type of the event.
     * @return the number of events of that type recorded so far.
     */
    protected long countEvents(final String type) {
        return jdbc.sql("SELECT count(*) FROM security_events WHERE type = ?").param(type).query(Long.class).single();
    }

    /**
     * Posts a request, as the page script does, in a browser session.
     *
     * @param path    path of the endpoint.
     * @param session the browser session.
     * @return the answer.
     * @throws Exception if the request cannot be performed.
     */
    protected ResultActions postJson(final String path, final MockHttpSession session) throws Exception {
        return getMockMvc().perform(post(path).session(session).with(csrf())
                .with(AbstractMfaFlow::sendsTheSessionCookie).contentType(MediaType.APPLICATION_JSON));
    }

    /**
     * Posts an assertion to the authentication endpoint, after asking for the options of the ceremony as the page
     * script does.
     *
     * @param session the browser session.
     * @return the answer of the authentication endpoint.
     * @throws Exception if a request cannot be performed.
     */
    protected ResultActions authenticateWithPasskey(final MockHttpSession session) throws Exception {
        postJson(AUTHENTICATION_OPTIONS, session);
        return getMockMvc().perform(post(AUTHENTICATION).session(session).with(csrf())
                .with(AbstractMfaFlow::sendsTheSessionCookie).contentType(MediaType.APPLICATION_JSON)
                .content(ASSERTION));
    }

    /**
     * Generates a random identifier in the form the framework stores them: unpadded base64url.
     *
     * @return the identifier.
     */
    private static String randomIdentifier() {
        final var bytes = new byte[HANDLE_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * A seeded passkey.
     *
     * @param userHandle   identifier of the user entity the passkey belongs to.
     * @param credentialId identifier of the credential.
     */
    record SeededPasskey(String userHandle, String credentialId) {
    }
}

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

package com.irurueta.authserver.authorization.infrastructure.persistence.dev;

import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a demo user, a confidential BFF client and a public device-flow client when the {@code dev} profile is active,
 * so a freshly started authorization server has someone to sign in, a client to sign in through and a client for the
 * OAuth 2.0 Device Authorization Grant ({@code device-client}, which the polling command line tool of the
 * {@code service-client} uses).
 *
 * <p>The {@code device-client} is dev-only on purpose: it is a public client that anybody who can reach the server can
 * use to start a device flow, and its user-facing name and scopes are those of a demo. A deployment registers its own
 * device clients through the admin API with the {@code urn:ietf:params:oauth:grant-type:device_code} grant type.
 *
 * <p>Purpose: local development and the end-to-end tests. Started with
 * {@code spring-boot:run -Dspring-boot.run.profiles=dev}, it lets a developer sign in through the BFF by hand. The
 * {@code e2e-tests} module ({@code SignInSmokeIT}) starts the <em>packaged</em> jar with the {@code dev} profile and
 * reads the generated credentials from the log lines below.
 *
 * <p>Why it lives in {@code src/main} although it only seeds demo data: the end-to-end tests run the real jar, and
 * a class under {@code src/test} never reaches it. It is inert everywhere else: without the {@code dev} profile the
 * bean is not even created. Never activate that profile outside local development.
 *
 * <p>It lives in the persistence adapter, next to the Flyway migrations, because it writes the tables those
 * migrations create: a schema change that breaks it is then caught by this module's own tests.
 *
 * <p>Secrets are generated at first start and logged once as {@code DEV ONLY} warnings; nothing is committed.
 * Running it again does not change existing data.
 */
@Slf4j
@Component
@Profile("dev")
@RequiredArgsConstructor
public class DevDataInitializer implements ApplicationRunner {

    /** Username of the demo user. */
    static final String DEMO_USERNAME = "demo";

    /** Client id of the public client of the device authorization grant. */
    static final String DEVICE_CLIENT_ID = "device-client";

    /** Grant type of the device authorization grant. */
    static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /**
     * Scopes of the device client. {@code openid} is left out on purpose: Spring Authorization Server refuses it in a
     * device authorization request, because the device flow issues no ID token.
     */
    private static final List<String> DEVICE_SCOPES = List.of("profile", "documents.read");

    /** Lifetime of the access tokens of the device client. */
    private static final Duration DEVICE_ACCESS_TOKEN_TTL = Duration.ofMinutes(10);

    /** Lifetime of the refresh tokens of the device client. */
    private static final Duration DEVICE_REFRESH_TOKEN_TTL = Duration.ofHours(8);

    /** Number of random bytes of generated secrets. */
    private static final int SECRET_BYTES = 24;

    /** Source of randomness for generated secrets. */
    private final SecureRandom random = new SecureRandom();

    /** JDBC client used to insert the demo user. */
    private final JdbcClient jdbc;

    /** Encoder of generated secrets. */
    private final PasswordEncoder encoder;

    /** Repository where the BFF client is stored. */
    private final ClientRegistrationRepository clients;

    /**
     * Redirect URIs of the BFF client ({@code authserver.clients.bff.redirect-uris}, which the {@code dev} profile
     * sets to the local BFF); empty when not configured.
     */
    @Value("${authserver.clients.bff.redirect-uris:}")
    private final List<String> bffRedirectUris;

    /**
     * Post-logout redirect URIs of the BFF client ({@code authserver.clients.bff.post-logout-redirect-uris}); empty
     * when not configured.
     */
    @Value("${authserver.clients.bff.post-logout-redirect-uris:}")
    private final List<String> bffPostLogoutRedirectUris;

    /** Audience of the authorization server's own API ({@code authserver.api.audience}). */
    @Value("${authserver.api.audience:" + DefaultClientDefinitions.DEFAULT_API_AUDIENCE + "}")
    private final String apiAudience;

    /**
     * Creates the demo user, the BFF client and the device client when they do not exist yet.
     *
     * @param args application arguments (unused).
     */
    @Override
    @Transactional
    public void run(final ApplicationArguments args) {
        createDemoUser();
        createBffClient();
        createDeviceClient();
    }

    /**
     * Creates the demo user, with a generated password, unless it already exists.
     */
    private void createDemoUser() {
        final var exists = jdbc.sql("SELECT count(*) FROM users WHERE username = ?")
                .param(DEMO_USERNAME).query(Integer.class).single() > 0;
        if (exists) {
            return;
        }
        final var password = generateSecret();
        final var id = UUID.randomUUID();
        jdbc.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(id, DEMO_USERNAME).update();
        jdbc.sql("INSERT INTO user_authorities (user_id, authority) VALUES (?, ?)")
                .params(id, "ROLE_USER").update();
        jdbc.sql("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)")
                .params(id, encoder.encode(password)).update();
        log.warn("DEV ONLY, never use outside local development: created demo user '{}' with generated password: {}",
                DEMO_USERNAME, password);
    }

    /**
     * Creates the BFF client from its default definition and the configured redirect URIs, with a generated secret,
     * unless it already exists or no redirect URI is configured.
     */
    private void createBffClient() {
        if (clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID).isPresent()) {
            return;
        }
        if (bffRedirectUris.isEmpty()) {
            log.warn("DEV ONLY: client '{}' not created, authserver.clients.bff.redirect-uris is not configured",
                    DefaultClientDefinitions.BFF_CLIENT_ID);
            return;
        }
        final var secret = generateSecret();
        clients.save(DefaultClientDefinitions.bff(bffRedirectUris, apiAudience, bffPostLogoutRedirectUris),
                encoder.encode(secret));
        log.warn("DEV ONLY, never use outside local development: created client '{}' with generated secret: {}",
                DefaultClientDefinitions.BFF_CLIENT_ID, secret);
    }

    /**
     * Creates the public device client, which has no secret and needs no redirect URI, unless it already exists. It
     * requires the user's consent to the requested scopes, as the verification page asks for it.
     */
    private void createDeviceClient() {
        if (clients.findByClientId(DEVICE_CLIENT_ID).isPresent()) {
            return;
        }
        clients.save(new ClientRegistration(DEVICE_CLIENT_ID, "Device flow demo", false, List.of("none"),
                List.of(DEVICE_CODE_GRANT, "refresh_token"), List.of(), DEVICE_SCOPES, true,
                List.of(DefaultClientDefinitions.RESOURCE_SERVER_AUDIENCE, apiAudience), DEVICE_ACCESS_TOKEN_TTL,
                DEVICE_REFRESH_TOKEN_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), true, false,
                null, null, null, null, false),
                null);
        log.warn("DEV ONLY, never use outside local development: created public client '{}' for the device flow",
                DEVICE_CLIENT_ID);
    }

    /**
     * Generates a random URL-safe secret.
     *
     * @return the secret.
     */
    private String generateSecret() {
        final var bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

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

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a demo user and a confidential BFF client when the {@code dev} profile is active. Secrets are generated
 * at first start and logged once; nothing is committed. Running it again does not change existing data.
 */
@Component
@Profile("dev")
public class DevDataInitializer implements ApplicationRunner {

    /** Username of the demo user. */
    static final String DEMO_USERNAME = "demo";

    /** Client id of the BFF client. */
    static final String BFF_CLIENT_ID = "bff";

    /** Redirect URI of the BFF client. */
    static final String BFF_REDIRECT_URI = "http://localhost:8080/login/oauth2/code/bff";

    /** Logger. */
    private static final Logger LOG = LoggerFactory.getLogger(DevDataInitializer.class);

    /** Number of random bytes of generated secrets. */
    private static final int SECRET_BYTES = 24;

    /** Lifetime of access tokens issued to the demo client. */
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(10);

    /** Source of randomness for generated secrets. */
    private final SecureRandom random = new SecureRandom();

    /** JDBC client used to insert the demo user. */
    private final JdbcClient jdbc;

    /** Encoder of generated secrets. */
    private final PasswordEncoder encoder;

    /** Repository where the BFF client is stored. */
    private final RegisteredClientRepository clients;

    /**
     * Creates the initializer.
     *
     * @param client           JDBC client used to insert the demo user.
     * @param passwordEncoder  encoder of generated secrets.
     * @param repository       repository where the BFF client is stored.
     */
    public DevDataInitializer(
            final JdbcClient client, final PasswordEncoder passwordEncoder,
            final RegisteredClientRepository repository) {
        this.jdbc = client;
        this.encoder = passwordEncoder;
        this.clients = repository;
    }

    /**
     * Creates the demo user and the BFF client when they do not exist yet.
     *
     * @param args application arguments (unused).
     */
    @Override
    @Transactional
    public void run(final ApplicationArguments args) {
        createDemoUser();
        createBffClient();
    }

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
        LOG.warn("DEV ONLY, never use outside local development: created demo user '{}' with generated password: {}",
                DEMO_USERNAME, password);
    }

    private void createBffClient() {
        if (clients.findByClientId(BFF_CLIENT_ID) != null) {
            return;
        }
        final var secret = generateSecret();
        final var client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(BFF_CLIENT_ID)
                .clientSecret(encoder.encode(secret))
                .clientName("Backend for Frontend")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(BFF_REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ACCESS_TOKEN_TTL).build())
                .build();
        clients.save(client);
        LOG.warn("DEV ONLY, never use outside local development: created client '{}' with generated secret: {}",
                BFF_CLIENT_ID, secret);
    }

    private String generateSecret() {
        final var bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

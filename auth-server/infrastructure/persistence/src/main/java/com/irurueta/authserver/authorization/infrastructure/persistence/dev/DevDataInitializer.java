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
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a demo user and a confidential BFF client when the {@code dev} profile is active, so a freshly started
 * authorization server has someone to sign in and a client to sign in through.
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
     * Creates the BFF client from its default definition, with a generated secret, unless it already exists.
     */
    private void createBffClient() {
        if (clients.findByClientId(DefaultClientDefinitions.BFF_CLIENT_ID).isPresent()) {
            return;
        }
        final var secret = generateSecret();
        clients.save(DefaultClientDefinitions.bff(), encoder.encode(secret));
        log.warn("DEV ONLY, never use outside local development: created client '{}' with generated secret: {}",
                DefaultClientDefinitions.BFF_CLIENT_ID, secret);
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

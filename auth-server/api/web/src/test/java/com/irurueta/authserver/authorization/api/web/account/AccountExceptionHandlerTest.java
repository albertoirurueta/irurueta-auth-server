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

package com.irurueta.authserver.authorization.api.web.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordException;
import com.irurueta.authserver.authorization.domain.password.InvalidCredentialsException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordViolation;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

/**
 * Unit tests of {@link AccountExceptionHandler}.
 */
class AccountExceptionHandlerTest {

    /** Handler under test. */
    private final AccountExceptionHandler handler = new AccountExceptionHandler();

    /**
     * Checks that the broken rules are listed.
     */
    @Test
    void handleInvalidPassword_whenViolationsExist_listsThem() {
        final var response = handler.handleInvalidPassword(
                new InvalidPasswordException(List.of(PasswordViolation.TOO_SHORT)));

        final var body = response.getBody();
        assertNotNull(body);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(URI.create("urn:problem:account:invalid-password"), body.getType());
        assertEquals(List.of("TOO_SHORT"), body.getProperties().get(AccountExceptionHandler.VIOLATIONS_PROPERTY));
    }

    /**
     * Checks the compromised password answer.
     */
    @Test
    void handleCompromisedPassword_whenCalled_answersBadRequest() {
        final var response = handler.handleCompromisedPassword(new CompromisedPasswordException("known"));

        final var body = response.getBody();
        assertNotNull(body);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("known", body.getDetail());
        assertEquals("Compromised password", body.getTitle());
    }

    /**
     * Checks the wrong credentials answer.
     */
    @Test
    void handleInvalidCredentials_whenCalled_answersBadRequest() {
        final var response = handler.handleInvalidCredentials(new InvalidCredentialsException("wrong"));

        final var body = response.getBody();
        assertNotNull(body);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("wrong", body.getDetail());
    }

    /**
     * Checks the invalid token answer.
     */
    @Test
    void handleInvalidToken_whenCalled_answersBadRequest() {
        final var response = handler.handleInvalidToken(new InvalidAccountTokenException());

        final var body = response.getBody();
        assertNotNull(body);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(URI.create("urn:problem:account:invalid-token"), body.getType());
    }
}

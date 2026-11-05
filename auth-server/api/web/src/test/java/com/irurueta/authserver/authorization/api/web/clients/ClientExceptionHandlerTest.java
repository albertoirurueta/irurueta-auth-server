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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.domain.clients.ClientAlreadyExistsException;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

/**
 * Unit tests of {@link ClientExceptionHandler}.
 */
class ClientExceptionHandlerTest {

    /** Handler under test. */
    private final ClientExceptionHandler handler = new ClientExceptionHandler();

    /**
     * An unknown client maps to 404.
     */
    @Test
    void handleNotFound_whenCalled_answersNotFound() {
        final var response = handler.handleNotFound(new ClientNotFoundException("x"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("urn:problem:client:not-found", response.getBody().getType().toString());
    }

    /**
     * A duplicate maps to 409.
     */
    @Test
    void handleAlreadyExists_whenCalled_answersConflict() {
        final var response = handler.handleAlreadyExists(new ClientAlreadyExistsException("x"));

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("urn:problem:client:already-exists", response.getBody().getType().toString());
    }

    /**
     * An invalid definition maps to 400.
     */
    @Test
    void handleInvalid_whenCalled_answersBadRequest() {
        final var response = handler.handleInvalid(new IllegalArgumentException("bad"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("bad", response.getBody().getDetail());
    }
}

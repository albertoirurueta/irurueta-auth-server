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


package com.irurueta.authserver.serviceclient;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.application.documents.ListDocumentsUseCase;
import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.ServiceTokens;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.json.JsonMapper;

/**
 * Unit tests of {@link ClientCredentialsCli}.
 */
@ExtendWith(MockitoExtension.class)
class ClientCredentialsCliTest {

    /** Lists the documents. */
    @Mock
    private ListDocumentsUseCase listDocumentsUseCase;

    /** Gives the token the call used. */
    @Mock
    private ServiceTokens serviceTokens;

    /** Writes the lines. */
    @Mock
    private CliOutput output;

    /** Writes a document as JSON; the real one. */
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    /** Runner under test, without the token. */
    private ClientCredentialsCli cli;

    /**
     * Creates the runner under test.
     */
    @BeforeEach
    void setUp() {
        cli = new ClientCredentialsCli(listDocumentsUseCase, serviceTokens, output, jsonMapper,
                new CliProperties(false, null));
    }

    /**
     * Verifies that every document is printed as a JSON line and the token is not.
     */
    @Test
    void run_whenTokenIsNotRequested_printsOneJsonLinePerDocument() {
        when(listDocumentsUseCase.execute()).thenReturn(
                List.of(new Document("1", "alice", "A"), new Document("2", "bob", "B")));

        cli.run();

        final var ordered = inOrder(output);
        ordered.verify(output).line("{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"A\"}");
        ordered.verify(output).line("{\"id\":\"2\",\"owner\":\"bob\",\"title\":\"B\"}");
        verifyNoInteractions(serviceTokens);
    }

    /**
     * Verifies that the token is printed after the documents when asked.
     */
    @Test
    void run_whenTokenIsRequested_printsTheTokenLast() {
        final var withToken = new ClientCredentialsCli(listDocumentsUseCase, serviceTokens, output, jsonMapper,
                new CliProperties(true, null));
        when(listDocumentsUseCase.execute()).thenReturn(List.of(new Document("1", "alice", "A")));
        when(serviceTokens.clientCredentialsToken()).thenReturn("cc-token");

        withToken.run();

        final var ordered = inOrder(output);
        ordered.verify(output).line("{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"A\"}");
        ordered.verify(output).line("Access token: cc-token");
    }

    /**
     * Verifies that a failure reaches the caller, so the process ends with a non-zero exit code, and prints nothing.
     */
    @Test
    void run_whenDocumentsCannotBeRead_throwsAndPrintsNothing() {
        final var failure = new DocumentAccessException("refused", null);
        when(listDocumentsUseCase.execute()).thenThrow(failure);

        assertSame(failure, assertThrows(DocumentAccessException.class, () -> cli.run()));

        verify(output, never()).line(anyString());
    }
}

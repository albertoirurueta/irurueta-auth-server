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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.application.documents.ListDocumentsOnBehalfOfUseCase;
import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.ServiceTokens;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.json.JsonMapper;

/**
 * Unit tests of {@link TokenExchangeCli}.
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeCliTest {

    /** The user's token. */
    private static final String SUBJECT_TOKEN = "user-token";

    /** Lists the documents of a user. */
    @Mock
    private ListDocumentsOnBehalfOfUseCase listDocumentsOnBehalfOfUseCase;

    /** Gives the exchanged token. */
    @Mock
    private ServiceTokens serviceTokens;

    /** Writes the lines. */
    @Mock
    private CliOutput output;

    /** Writes a document as JSON; the real one. */
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    /**
     * Verifies that the documents of the user are printed as JSON lines.
     */
    @Test
    void run_whenSubjectTokenIsSet_printsOneJsonLinePerDocument() {
        when(listDocumentsOnBehalfOfUseCase.execute(SUBJECT_TOKEN))
                .thenReturn(List.of(new Document("1", "alice", "A")));

        cli(new CliProperties(false, SUBJECT_TOKEN)).run();

        verify(output).line("{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"A\"}");
        verifyNoInteractions(serviceTokens);
    }

    /**
     * Verifies that the exchanged token is printed last when asked.
     */
    @Test
    void run_whenTokenIsRequested_printsTheExchangedTokenLast() {
        when(listDocumentsOnBehalfOfUseCase.execute(SUBJECT_TOKEN))
                .thenReturn(List.of(new Document("1", "alice", "A")));
        when(serviceTokens.exchangedToken(SUBJECT_TOKEN)).thenReturn("exchanged");

        cli(new CliProperties(true, SUBJECT_TOKEN)).run();

        final var ordered = inOrder(output);
        ordered.verify(output).line("{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"A\"}");
        ordered.verify(output).line("Access token: exchanged");
    }

    /**
     * Verifies that a missing subject token fails, naming the variable, and calls nothing.
     */
    @Test
    void run_whenSubjectTokenIsMissing_throwsIllegalStateException() {
        final var cli = cli(new CliProperties(false, " "));

        final var error = assertThrows(IllegalStateException.class, () -> cli.run());

        assertTrue(error.getMessage().contains("SERVICE_CLIENT_SUBJECT_TOKEN"));
        assertFalse(error.getMessage().contains(SUBJECT_TOKEN));
        verifyNoInteractions(listDocumentsOnBehalfOfUseCase);
        verify(output, never()).line(anyString());
    }

    /**
     * Builds the runner.
     *
     * @param properties its settings.
     * @return the runner.
     */
    private TokenExchangeCli cli(final CliProperties properties) {
        return new TokenExchangeCli(listDocumentsOnBehalfOfUseCase, serviceTokens, output, jsonMapper, properties);
    }
}

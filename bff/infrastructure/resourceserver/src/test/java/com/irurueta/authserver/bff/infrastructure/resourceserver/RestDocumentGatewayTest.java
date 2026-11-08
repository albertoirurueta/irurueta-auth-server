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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.bff.domain.documents.Document;
import com.irurueta.authserver.bff.domain.documents.DocumentNotFoundException;
import com.irurueta.authserver.bff.domain.documents.DocumentsForbiddenException;
import com.irurueta.authserver.bff.domain.documents.DocumentsStepUpRequiredException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnauthorizedException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnavailableException;
import com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.model.DocumentResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;

/**
 * Unit tests of {@link RestDocumentGateway}.
 */
@ExtendWith(MockitoExtension.class)
class RestDocumentGatewayTest {

    /** Identifier of the document. */
    private static final String ID = "7";

    /** Seconds of the maximum age of the step-up challenge. */
    private static final long MAX_AGE_SECONDS = 300L;

    /** A status code no {@link HttpStatus} constant names. */
    private static final int UNKNOWN_STATUS = 599;

    /** Documents client generated from the resource server's contract. */
    @Mock
    private DocumentsApi documentsApi;

    /** Maps the generated model; the real one. */
    @Spy
    private DocumentMapper documentMapper;

    /** Reads the step-up challenge; the real one. */
    @Spy
    private StepUpChallengeMapper stepUpChallengeMapper;

    /** Gateway under test. */
    @InjectMocks
    private RestDocumentGateway gateway;

    /**
     * Provides each error status of the resource server with the domain exception it becomes.
     *
     * @return the status and the expected exception type.
     */
    private static Stream<Arguments> errorStatuses() {
        return Stream.of(
                Arguments.of(HttpStatus.UNAUTHORIZED.value(), DocumentsUnauthorizedException.class),
                Arguments.of(HttpStatus.FORBIDDEN.value(), DocumentsForbiddenException.class),
                Arguments.of(HttpStatus.NOT_FOUND.value(), DocumentNotFoundException.class),
                Arguments.of(HttpStatus.BAD_REQUEST.value(), DocumentsUnavailableException.class),
                Arguments.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), DocumentsUnavailableException.class),
                Arguments.of(UNKNOWN_STATUS, DocumentsUnavailableException.class));
    }

    /**
     * Verifies that the documents of the resource server are mapped onto the domain.
     */
    @Test
    void list_whenResourceServerAnswersDocuments_mapsThem() {
        when(documentsApi.listDocuments()).thenReturn(
                List.of(new DocumentResponse().id("1").owner("alice").title("Title").content("Body")));

        assertEquals(List.of(new Document("1", "alice", "Title", "Body")), gateway.list());
    }

    /**
     * Verifies that an answer without a body is an empty list, never {@code null}.
     */
    @Test
    void list_whenResourceServerAnswersNoBody_returnsAnEmptyList() {
        when(documentsApi.listDocuments()).thenReturn(null);

        assertTrue(gateway.list().isEmpty());
    }

    /**
     * Verifies that a token that cannot be obtained or renewed is reported as unauthorized.
     */
    @Test
    void list_whenTokenCannotBeObtained_throwsUnauthorized() {
        final var failure = new ClientAuthorizationException(new OAuth2Error("invalid_grant"), "bff");
        when(documentsApi.listDocuments()).thenThrow(failure);

        final var error = assertThrows(DocumentsUnauthorizedException.class, () -> gateway.list());

        assertSame(failure, error.getCause());
    }

    /**
     * Verifies that an unreachable resource server is reported as unavailable.
     */
    @Test
    void list_whenResourceServerIsUnreachable_throwsUnavailable() {
        when(documentsApi.listDocuments()).thenThrow(new ResourceAccessException("connection refused"));

        assertThrows(DocumentsUnavailableException.class, () -> gateway.list());
    }

    /**
     * Verifies that a server error of the resource server is reported as unavailable.
     */
    @Test
    void list_whenResourceServerFails_throwsUnavailable() {
        when(documentsApi.listDocuments()).thenThrow(HttpServerErrorException.create(
                HttpStatus.BAD_GATEWAY, "Bad Gateway", HttpHeaders.EMPTY, new byte[0], StandardCharsets.UTF_8));

        assertThrows(DocumentsUnavailableException.class, () -> gateway.list());
    }

    /**
     * Verifies that a deletion goes to the resource server with the identifier.
     */
    @Test
    void deleteById_whenResourceServerDeletes_returnsNormally() {
        when(documentsApi.deleteDocumentWithHttpInfo(ID)).thenReturn(ResponseEntity.noContent().build());

        gateway.deleteById(ID);

        verify(documentsApi).deleteDocumentWithHttpInfo(ID);
    }

    /**
     * Verifies that every error status of the resource server becomes its domain exception.
     *
     * @param status   the status the resource server answers.
     * @param expected the domain exception it must become.
     */
    @ParameterizedTest
    @MethodSource("errorStatuses")
    void deleteById_whenResourceServerAnswersAnError_throwsTheMatchingDomainException(
            final int status, final Class<? extends RuntimeException> expected) {
        final var failure = status == UNKNOWN_STATUS
                ? new RestClientResponseException("unknown", status, "", HttpHeaders.EMPTY, new byte[0],
                        StandardCharsets.UTF_8)
                : HttpClientErrorException.create(HttpStatus.valueOf(status), "", HttpHeaders.EMPTY, new byte[0],
                        StandardCharsets.UTF_8);
        when(documentsApi.deleteDocumentWithHttpInfo(ID)).thenThrow(failure);

        final var error = assertThrows(expected, () -> gateway.deleteById(ID));

        assertSame(failure, error.getCause());
    }

    /**
     * Verifies that a {@code 401} carrying a step-up challenge becomes a step-up request with its values.
     */
    @Test
    void deleteById_whenResourceServerAsksForStepUp_throwsStepUpRequired() {
        final var headers = new HttpHeaders();
        headers.add(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_user_authentication\", "
                + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"" + MAX_AGE_SECONDS + "\"");
        final var failure = HttpClientErrorException.create(HttpStatus.UNAUTHORIZED, "", headers, new byte[0],
                StandardCharsets.UTF_8);
        when(documentsApi.deleteDocumentWithHttpInfo(ID)).thenThrow(failure);

        final var error = assertThrows(DocumentsStepUpRequiredException.class, () -> gateway.deleteById(ID));

        assertEquals(Optional.of("urn:irurueta:acr:mfa"), error.getAcrValues());
        assertEquals(Optional.of(Duration.ofSeconds(MAX_AGE_SECONDS)), error.getMaxAge());
        assertSame(failure, error.getCause());
    }

    /**
     * Verifies that a {@code 401} with another bearer challenge stays an unauthorized session.
     */
    @Test
    void deleteById_whenResourceServerRefusesTheToken_throwsUnauthorized() {
        final var headers = new HttpHeaders();
        headers.add(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        when(documentsApi.deleteDocumentWithHttpInfo(ID)).thenThrow(HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "", headers, new byte[0], StandardCharsets.UTF_8));

        assertThrows(DocumentsUnauthorizedException.class, () -> gateway.deleteById(ID));
    }
}

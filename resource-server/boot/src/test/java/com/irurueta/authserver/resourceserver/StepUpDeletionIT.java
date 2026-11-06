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
package com.irurueta.authserver.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.resourceserver.api.web.documents.DocumentController;
import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Follows what a user goes through when deleting a document (RFC 9470 step-up), against the whole resource server
 * filter chain with real signed JWTs shaped like the ones the authorization server issues: a password-only token is
 * challenged with {@code insufficient_user_authentication}, and the same user holding a token of the multi-factor
 * class with a recent {@code auth_time} (what the authorization server issues after the step-up) deletes the document.
 * The rule is never relaxed: an old authentication is challenged again.
 */
@SpringBootTest
@AutoConfigureMockMvc
class StepUpDeletionIT {

    /** Subject of the tokens. */
    private static final String SUBJECT = "step-up-user";

    /** Issuer claim of the tokens. */
    private static final String ISSUER = "http://localhost:9000";

    /** Audience the resource server accepts by default. */
    private static final String AUDIENCE = "resource-server";

    /** Scope that allows deleting documents. */
    private static final String DELETE_SCOPE = "documents.delete";

    /** Scope that allows reading documents. */
    private static final String READ_SCOPE = "documents.read";

    /** Class of a password-only authentication. */
    private static final String PASSWORD_ACR = "urn:irurueta:acr:pwd";

    /** Class of a multi-factor authentication. */
    private static final String MULTI_FACTOR_ACR = "urn:irurueta:acr:mfa";

    /** The challenge the default policy answers. */
    private static final String CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
            + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\"";

    /** Store of the documents. */
    @Autowired
    private DocumentRepository documentRepository;

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Points the resource server's decoder at the public half of the generated key.
     *
     * @param registry registry of the test properties.
     * @throws IOException if the PEM file cannot be written.
     */
    @DynamicPropertySource
    static void publicKeyLocation(final DynamicPropertyRegistry registry) throws IOException {
        TestTokens.publicKeyLocation(registry);
    }

    /**
     * Verifies the whole story: the password-only token is challenged and keeps the document; the token obtained
     * after the step-up deletes it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deleteDocument_whenUserStepsUp_isChallengedThenDeletes() throws Exception {
        documentRepository.save(new Document("step-up-story", SUBJECT, "Story", "text"));
        final var path = DocumentController.PATH + "/step-up-story";

        mockMvc.perform(delete(path).header(HttpHeaders.AUTHORIZATION, token(PASSWORD_ACR, Instant.now())))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, CHALLENGE));
        assertEquals(1, countOf("step-up-story"));

        mockMvc.perform(delete(path).header(HttpHeaders.AUTHORIZATION, token(MULTI_FACTOR_ACR, Instant.now())))
                .andExpect(status().isNoContent());
        assertEquals(0, countOf("step-up-story"));
    }

    /**
     * Verifies that a multi-factor token whose authentication is older than the policy tolerates is challenged.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void deleteDocument_whenMultiFactorAuthenticationIsStale_isChallenged() throws Exception {
        documentRepository.save(new Document("step-up-stale", SUBJECT, "Stale", "text"));
        final var stale = Instant.now().minus(TestTokens.TOKEN_TTL).minusSeconds(1);

        mockMvc.perform(delete(DocumentController.PATH + "/step-up-stale")
                        .header(HttpHeaders.AUTHORIZATION, token(MULTI_FACTOR_ACR, stale)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, CHALLENGE));
        assertEquals(1, countOf("step-up-stale"));
    }

    /**
     * Verifies that the step-up only guards deletion: a password-only token still reads documents.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenAuthenticationIsPasswordOnly_isNotChallenged() throws Exception {
        mockMvc.perform(get(DocumentController.PATH).header(HttpHeaders.AUTHORIZATION,
                        TestTokens.bearer(ISSUER, SUBJECT, List.of(AUDIENCE), READ_SCOPE, List.of(),
                                Map.of("acr", PASSWORD_ACR, "auth_time", Instant.now().getEpochSecond()))))
                .andExpect(status().isOk());
    }

    /**
     * Counts the documents of the subject that have an identifier.
     *
     * @param id identifier of the document.
     * @return how many documents of the subject have it.
     */
    private long countOf(final String id) {
        return documentRepository.findByOwner(SUBJECT).stream().filter(document -> id.equals(document.id())).count();
    }

    /**
     * Builds an {@code Authorization} header value for a token that may delete documents.
     *
     * @param acr      authentication context class reached.
     * @param authTime instant the user authenticated.
     * @return the header value.
     */
    private static String token(final String acr, final Instant authTime) {
        return TestTokens.bearer(ISSUER, SUBJECT, List.of(AUDIENCE), DELETE_SCOPE, List.of(),
                Map.of("acr", acr, "auth_time", authTime.getEpochSecond()));
    }
}

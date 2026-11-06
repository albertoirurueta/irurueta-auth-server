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

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.resourceserver.api.web.documents.DocumentController;
import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.io.IOException;
import java.time.Duration;
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
 * Integration tests of {@link com.irurueta.authserver.resourceserver.api.web.security.SecurityConfig} through the
 * whole filter chain, against the test-only {@link ProtectedTestController}.
 *
 * <p>The real-token tests sign JWTs with an RSA key generated here and point
 * {@code spring.security.oauth2.resourceserver.jwt.public-key-location} at its public half. Spring Boot only builds
 * a decoder from that key when {@code issuer-uri} is blank (otherwise it resolves the issuer's metadata over HTTP),
 * so the tests blank it. The configured audiences still apply: the audience validator the application really uses
 * is exercised without starting the authorization server. No key is ever committed.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Subject of the test bearer token. */
    private static final String SUBJECT = "demo";

    /** Issuer claim of the test tokens. */
    private static final String ISSUER = "http://localhost:9000";

    /** Audience the resource server accepts by default. */
    private static final String ACCEPTED_AUDIENCE = "resource-server";

    /** Owner of the documents that are not the caller's. */
    private static final String OTHER_OWNER = "someone-else";

    /** Audience of a token issued to another client. */
    private static final String OTHER_AUDIENCE = "bff";

    /** Lifetime of the test tokens. */
    private static final Duration TOKEN_TTL = TestTokens.TOKEN_TTL;

    /** Scope that allows reading documents. */
    private static final String READ_SCOPE = "documents.read";

    /** Scope that allows deleting documents. */
    private static final String DELETE_SCOPE = "documents.delete";

    /** The RFC 9470 challenge the default policy answers. */
    private static final String STEP_UP_CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
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
     * Verifies that a request without a bearer token is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that an authenticated request reaches the endpoint with the token's claims.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenIsValid_exposesTheTokenToTheEndpoint() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH).with(jwt().jwt(token -> token.subject(SUBJECT))))
                .andExpect(status().isOk())
                .andExpect(content().string(SUBJECT));
    }

    /**
     * Verifies that a signed token issued to the accepted audience passes the real decoder.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenAudienceIsAccepted_returnsOk() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(ACCEPTED_AUDIENCE))))
                .andExpect(status().isOk())
                .andExpect(content().string(SUBJECT));
    }

    /**
     * Verifies that a signed token issued to another client is rejected by the audience validator.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenAudienceIsOther_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(OTHER_AUDIENCE))))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a signed token without any audience is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenHasNoAudience_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of())))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that an audience failure answers with the RFC 6750 {@code invalid_token} challenge.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenIsInvalid_challengesWithInvalidToken() throws Exception {
        mockMvc.perform(get(DocumentController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(OTHER_AUDIENCE), READ_SCOPE)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    /**
     * Verifies that listing documents needs the read scope, challenging with {@code insufficient_scope}.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenTokenLacksTheReadScope_returnsForbiddenWithInsufficientScope() throws Exception {
        mockMvc.perform(get(DocumentController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(ACCEPTED_AUDIENCE))))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("insufficient_scope")));
    }

    /**
     * Verifies that a caller sees only their own documents.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenTokenHasTheReadScope_listsOnlyTheCallersDocuments() throws Exception {
        documentRepository.save(new Document("it-own", SUBJECT, "Own", "text"));
        documentRepository.save(new Document("it-foreign", "someone-else", "Foreign", "text"));

        mockMvc.perform(get(DocumentController.PATH)
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(ACCEPTED_AUDIENCE), READ_SCOPE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == 'it-own')]").exists())
                .andExpect(jsonPath("$[?(@.id == 'it-foreign')]").doesNotExist());
    }

    /**
     * Verifies that deleting needs the delete scope.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenTokenLacksTheDeleteScope_deleteIsForbidden() throws Exception {
        documentRepository.save(new Document("it-keep", SUBJECT, "Keep", "text"));

        mockMvc.perform(delete(DocumentController.PATH + "/it-keep")
                        .header(HttpHeaders.AUTHORIZATION, bearer(ISSUER, List.of(ACCEPTED_AUDIENCE), READ_SCOPE)))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("insufficient_scope")));
        assertEquals(1, documentRepository.findByOwner(SUBJECT).stream()
                .filter(document -> "it-keep".equals(document.id())).count());
    }

    /**
     * Verifies that a caller with the delete scope deletes a document, and that deleting it again finds nothing.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenTokenHasTheDeleteScope_deletesOnceThenNotFound() throws Exception {
        documentRepository.save(new Document("it-delete", SUBJECT, "Delete", "text"));
        final var header = strongBearer(List.of(), Instant.now());

        mockMvc.perform(delete(DocumentController.PATH + "/it-delete").header(HttpHeaders.AUTHORIZATION, header))
                .andExpect(status().isNoContent());
        mockMvc.perform(delete(DocumentController.PATH + "/it-delete").header(HttpHeaders.AUTHORIZATION, header))
                .andExpect(status().isNotFound());
    }

    /**
     * Verifies that a caller with the delete scope cannot delete someone else's document: the answer is the same
     * {@code 404} as for a missing document, and the document stays.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenDeletingSomeoneElsesDocument_returnsNotFoundAndKeepsIt() throws Exception {
        documentRepository.save(new Document("it-foreign-delete", OTHER_OWNER, "Foreign", "text"));

        mockMvc.perform(delete(DocumentController.PATH + "/it-foreign-delete").header(HttpHeaders.AUTHORIZATION,
                        strongBearer(List.of(), Instant.now())))
                .andExpect(status().isNotFound());
        assertEquals(1, documentRepository.findByOwner(OTHER_OWNER).stream()
                .filter(document -> "it-foreign-delete".equals(document.id())).count());
    }

    /**
     * Verifies that an administrator with the delete scope deletes someone else's document.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenAnAdministratorDeletesSomeoneElsesDocument_returnsNoContent() throws Exception {
        documentRepository.save(new Document("it-admin-delete", OTHER_OWNER, "Foreign", "text"));

        mockMvc.perform(delete(DocumentController.PATH + "/it-admin-delete").header(HttpHeaders.AUTHORIZATION,
                        strongBearer(List.of("ROLE_ADMIN"), Instant.now())))
                .andExpect(status().isNoContent());
        assertEquals(0, documentRepository.findByOwner(OTHER_OWNER).stream()
                .filter(document -> "it-admin-delete".equals(document.id())).count());
    }

    /**
     * Verifies that a token with the delete scope but the password-level {@code acr} is answered with the RFC 9470
     * step-up challenge and leaves the document alone.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenAcrIsPassword_deleteRequiresStepUp() throws Exception {
        documentRepository.save(new Document("it-step-up-acr", SUBJECT, "Keep", "text"));

        mockMvc.perform(delete(DocumentController.PATH + "/it-step-up-acr").header(HttpHeaders.AUTHORIZATION,
                        bearer(ISSUER, List.of(ACCEPTED_AUDIENCE), DELETE_SCOPE, List.of(),
                                Map.of("acr", "urn:irurueta:acr:pwd", "auth_time", Instant.now().getEpochSecond()))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, STEP_UP_CHALLENGE));
        assertEquals(1, documentRepository.findByOwner(SUBJECT).stream()
                .filter(document -> "it-step-up-acr".equals(document.id())).count());
    }

    /**
     * Verifies that a token without the {@code acr} and {@code auth_time} claims requires step-up.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenClaimsAreMissing_deleteRequiresStepUp() throws Exception {
        mockMvc.perform(delete(DocumentController.PATH + "/anything").header(HttpHeaders.AUTHORIZATION,
                        bearer(ISSUER, List.of(ACCEPTED_AUDIENCE), DELETE_SCOPE)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, STEP_UP_CHALLENGE));
    }

    /**
     * Verifies that an old authentication requires step-up.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenAuthenticationIsOld_deleteRequiresStepUp() throws Exception {
        mockMvc.perform(delete(DocumentController.PATH + "/anything").header(HttpHeaders.AUTHORIZATION,
                        strongBearer(List.of(), Instant.now().minus(TOKEN_TTL).minusSeconds(1))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, STEP_UP_CHALLENGE));
    }

    /**
     * Builds an {@code Authorization} header value for a token with the delete scope and the strong {@code acr}.
     *
     * @param roles    roles of the caller; empty to leave the claim out.
     * @param authTime time the user authenticated.
     * @return the header value.
     */
    private static String strongBearer(final List<String> roles, final Instant authTime) {
        return bearer(ISSUER, List.of(ACCEPTED_AUDIENCE), DELETE_SCOPE, roles,
                Map.of("acr", "urn:irurueta:acr:mfa", "auth_time", authTime.getEpochSecond()));
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @return the header value.
     */
    private static String bearer(final String issuer, final List<String> audiences) {
        return bearer(issuer, audiences, "");
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @param scope     space-separated scopes of the token; empty to leave the claim out.
     * @return the header value.
     */
    private static String bearer(final String issuer, final List<String> audiences, final String scope) {
        return bearer(issuer, audiences, scope, List.of());
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @param scope     space-separated scopes of the token; empty to leave the claim out.
     * @param roles     roles of the caller; empty to leave the claim out.
     * @return the header value.
     */
    private static String bearer(final String issuer, final List<String> audiences, final String scope,
                                 final List<String> roles) {
        return bearer(issuer, audiences, scope, roles, Map.of());
    }

    /**
     * Builds an {@code Authorization} header value carrying a token signed with the generated key.
     *
     * @param issuer    issuer claim of the token.
     * @param audiences audience claim of the token; empty to leave the claim out.
     * @param scope     space-separated scopes of the token; empty to leave the claim out.
     * @param roles     roles of the caller; empty to leave the claim out.
     * @param extra     further claims of the token.
     * @return the header value.
     */
    private static String bearer(final String issuer, final List<String> audiences, final String scope,
                                 final List<String> roles, final Map<String, Object> extra) {
        return TestTokens.bearer(issuer, SUBJECT, audiences, scope, roles, extra);
    }
}

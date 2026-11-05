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

package com.irurueta.authserver.resourceserver.api.web.documents;

import com.irurueta.authserver.resourceserver.api.web.OpenApiConfig;
import com.irurueta.authserver.resourceserver.api.web.security.BearerAuthorities;
import com.irurueta.authserver.resourceserver.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.resourceserver.application.documents.ListDocumentsUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Documents API. Reading needs the {@code documents.read} scope (enforced by the filter chain) and deleting the
 * {@code documents.delete} scope (enforced by method security).
 */
@RestController
@RequestMapping(DocumentController.PATH)
@RequiredArgsConstructor
@Tag(name = "documents", description = "Documents of the authenticated user.")
@SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME)
public class DocumentController {

    /** Base path of the API. */
    public static final String PATH = "/api/documents";

    /** Use case that lists documents. */
    private final ListDocumentsUseCase listDocumentsUseCase;

    /** Use case that deletes a document. */
    private final DeleteDocumentUseCase deleteDocumentUseCase;

    // tag::resource-server-documents[]
    /**
     * Lists the documents of the caller; an administrator ({@code ROLE_ADMIN}) sees every document.
     *
     * @param authentication the authenticated caller.
     * @return the documents.
     */
    @GetMapping
    @Operation(summary = "Lists documents",
            description = "Lists the caller's documents; an administrator sees all. Needs scope documents.read.")
    @ApiResponse(responseCode = "200", description = "The documents.")
    @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token.", content = @Content)
    @ApiResponse(responseCode = "403", description = "The token lacks the documents.read scope.", content = @Content)
    public List<DocumentResponse> list(final Authentication authentication) {
        final var documents = BearerAuthorities.isAdministrator(authentication)
                ? listDocumentsUseCase.listAll()
                : listDocumentsUseCase.listOwn(authentication.getName());
        return DocumentMapper.toResponses(documents);
    }

    // end::resource-server-documents[]

    // tag::resource-server-method-security[]
    /**
     * Deletes a document.
     *
     * @param id identifier of the document.
     * @return 204 when the document was deleted, 404 when it did not exist.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_documents.delete')")
    @Operation(summary = "Deletes a document", description = "Needs scope documents.delete.")
    @ApiResponse(responseCode = "204", description = "The document was deleted.", content = @Content)
    @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token.", content = @Content)
    @ApiResponse(responseCode = "403", description = "The token lacks the documents.delete scope.", content = @Content)
    @ApiResponse(responseCode = "404", description = "The document does not exist.", content = @Content)
    public ResponseEntity<Void> delete(@PathVariable final String id) {
        return deleteDocumentUseCase.execute(id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
    // end::resource-server-method-security[]
}

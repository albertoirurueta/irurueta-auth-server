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

import com.irurueta.authserver.resourceserver.api.web.security.BearerAuthorities;
import com.irurueta.authserver.resourceserver.api.web.v1.generated.api.DocumentsApi;
import com.irurueta.authserver.resourceserver.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.resourceserver.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.resourceserver.application.documents.ListDocumentsUseCase;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

/**
 * Documents API, as the contract {@code apis/resource-server/rest-server/resource-server-api-v1.yaml} describes it
 * through the generated {@link DocumentsApi}. Reading needs the {@code documents.read} scope (enforced by the filter
 * chain) and deleting the {@code documents.delete} scope (enforced by method security).
 */
@RestController
@RequiredArgsConstructor
public class DocumentController implements DocumentsApi {

    /** Base path of the API, as declared by the contract. */
    public static final String PATH = PATH_LIST_DOCUMENTS;

    /** Use case that lists documents. */
    private final ListDocumentsUseCase listDocumentsUseCase;

    /** Use case that deletes a document. */
    private final DeleteDocumentUseCase deleteDocumentUseCase;

    /** Maps the documents onto the generated DTO. */
    private final DocumentDtoMapper documentDtoMapper;

    // tag::resource-server-documents[]
    /**
     * Lists the documents of the caller; an administrator ({@code ROLE_ADMIN}) sees every document.
     *
     * @return the documents.
     */
    @Override
    public ResponseEntity<List<DocumentResponse>> listDocuments() {
        final var authentication = caller();
        final var documents = BearerAuthorities.isAdministrator(authentication)
                ? listDocumentsUseCase.listAll()
                : listDocumentsUseCase.listOwn(authentication.getName());
        return ResponseEntity.ok(documentDtoMapper.toResponses(documents));
    }

    // end::resource-server-documents[]

    // tag::resource-server-method-security[]
    /**
     * Deletes a document of the caller; an administrator ({@code ROLE_ADMIN}) may delete any document. Someone
     * else's document is answered like a missing one, so the answer never reveals that it exists.
     *
     * @param id identifier of the document.
     * @return 204 when the document was deleted, 404 when it does not exist or belongs to someone else.
     */
    @Override
    @PreAuthorize("hasAuthority('SCOPE_documents.delete')")
    public ResponseEntity<Void> deleteDocument(final String id) {
        final var authentication = caller();
        return deleteDocumentUseCase.execute(id, authentication.getName(),
                BearerAuthorities.isAdministrator(authentication))
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
    // end::resource-server-method-security[]

    /**
     * Returns the authenticated caller. The generated interface carries only the contract's parameters, so the
     * bearer token's authentication is taken from the security context, which the filter chain has filled.
     *
     * @return the authenticated caller.
     * @throws AuthenticationCredentialsNotFoundException if nobody is authenticated, answered 401 by the filter chain.
     */
    private static Authentication caller() {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException("No bearer token was authenticated");
        }
        return authentication;
    }
}

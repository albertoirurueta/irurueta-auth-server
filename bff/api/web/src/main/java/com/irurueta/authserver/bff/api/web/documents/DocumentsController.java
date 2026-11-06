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

package com.irurueta.authserver.bff.api.web.documents;

import com.irurueta.authserver.bff.api.web.v1.generated.api.DocumentsApi;
import com.irurueta.authserver.bff.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.bff.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.bff.application.documents.ListDocumentsUseCase;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lists and deletes the documents of the signed-in user, as the contract {@code apis/bff/rest-server/bff-api-v1.yaml}
 * describes them through the generated {@link DocumentsApi}. The failures of the use cases are answered by
 * {@link DocumentsExceptionHandler}.
 */
@RestController
@RequiredArgsConstructor
public class DocumentsController implements DocumentsApi {

    /** Lists the documents. */
    private final ListDocumentsUseCase listDocumentsUseCase;

    /** Deletes a document. */
    private final DeleteDocumentUseCase deleteDocumentUseCase;

    /** Maps the domain documents onto the generated DTO. */
    private final DocumentDtoMapper documentDtoMapper;

    // tag::bff-documents-controller[]
    /**
     * Lists the documents of the signed-in user.
     *
     * @return the documents.
     */
    @Override
    public ResponseEntity<List<DocumentResponse>> listDocuments() {
        return ResponseEntity.ok(listDocumentsUseCase.execute().stream().map(documentDtoMapper::toResponse).toList());
    }

    /**
     * Deletes a document of the signed-in user.
     *
     * @param id identifier of the document.
     * @return an empty {@code 204}.
     */
    @Override
    public ResponseEntity<Void> deleteDocument(final String id) {
        deleteDocumentUseCase.execute(id);
        return ResponseEntity.noContent().build();
    }
    // end::bff-documents-controller[]
}

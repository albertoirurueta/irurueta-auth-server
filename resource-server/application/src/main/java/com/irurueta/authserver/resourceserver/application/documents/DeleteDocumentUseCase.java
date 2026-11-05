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

package com.irurueta.authserver.resourceserver.application.documents;

import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that deletes a document on behalf of a caller. Only the owner of a document, or an administrator, may
 * delete it. A document the caller may not delete is reported exactly like a missing one, so that the answer never
 * reveals that a document with that identifier exists and belongs to someone else (the API answers {@code 404} in
 * both cases rather than {@code 403}).
 */
@Service
@RequiredArgsConstructor
public class DeleteDocumentUseCase {

    /** Port that stores the documents. */
    private final DocumentRepository documentRepository;

    // tag::resource-server-delete-ownership[]
    /**
     * Deletes a document when the caller owns it or is an administrator.
     *
     * @param id            identifier of the document.
     * @param caller        subject of the caller.
     * @param administrator whether the caller is an administrator, who may delete any document.
     * @return {@code true} when the document was deleted, {@code false} when it does not exist or the caller may not
     *         delete it (the two are deliberately indistinguishable).
     */
    public boolean execute(final String id, final String caller, final boolean administrator) {
        // Extension point (#4): the authentication-method check (the `amr` claim of the token, for example to require
        // a multi-factor login) attaches here, before the deletion, as a step-up requirement.
        final var allowed = documentRepository.findById(id)
                .filter(document -> administrator || document.owner().equals(caller))
                .isPresent();
        return allowed && documentRepository.deleteById(id);
    }
    // end::resource-server-delete-ownership[]
}

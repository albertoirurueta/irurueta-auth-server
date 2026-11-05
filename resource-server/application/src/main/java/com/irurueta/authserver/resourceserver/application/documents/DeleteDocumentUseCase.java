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
 * Use case that deletes a document.
 */
@Service
@RequiredArgsConstructor
public class DeleteDocumentUseCase {

    /** Port that stores the documents. */
    private final DocumentRepository documentRepository;

    /**
     * Deletes a document.
     *
     * @param id identifier of the document.
     * @return {@code true} when a document was deleted, {@code false} when it did not exist.
     */
    public boolean execute(final String id) {
        // Extension point (#4): the authentication-method check (the `amr` claim of the token, for example to require
        // a multi-factor login) attaches here, before the deletion, as a step-up requirement.
        return documentRepository.deleteById(id);
    }
}

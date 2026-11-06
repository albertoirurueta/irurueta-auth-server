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

package com.irurueta.authserver.bff.application.documents;

import com.irurueta.authserver.bff.domain.documents.DocumentGateway;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that deletes one document of the signed-in user. Whether the user may delete it (their own, or any document
 * for an administrator) is decided by the resource server, which reports someone else's document as missing.
 */
@Service
@RequiredArgsConstructor
public class DeleteDocumentUseCase {

    /** Port to the documents on the resource server. */
    private final DocumentGateway documentGateway;

    /**
     * Deletes a document.
     *
     * @param id identifier of the document.
     */
    public void execute(final String id) {
        documentGateway.deleteById(id);
    }
}

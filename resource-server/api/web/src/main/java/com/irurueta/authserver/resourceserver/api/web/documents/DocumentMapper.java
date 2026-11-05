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

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import java.util.List;

/**
 * Maps domain documents onto their web representation, so a domain model is never returned from a controller.
 */
final class DocumentMapper {

    /** Utility class: not meant to be instantiated. */
    private DocumentMapper() {
    }

    /**
     * Maps one document.
     *
     * @param document the domain document.
     * @return its web representation.
     */
    static DocumentResponse toResponse(final Document document) {
        return new DocumentResponse(document.id(), document.owner(), document.title(), document.content());
    }

    /**
     * Maps several documents, keeping their order.
     *
     * @param documents the domain documents.
     * @return their web representations.
     */
    static List<DocumentResponse> toResponses(final List<Document> documents) {
        return documents.stream().map(DocumentMapper::toResponse).toList();
    }
}

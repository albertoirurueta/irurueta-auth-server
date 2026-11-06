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

import com.irurueta.authserver.bff.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.bff.domain.documents.Document;
import org.springframework.stereotype.Component;

/**
 * Maps the domain documents onto the DTO generated from the contract; a controller never returns a domain model.
 */
@Component
public class DocumentDtoMapper {

    /**
     * Maps a document.
     *
     * @param document the domain document.
     * @return its web representation.
     */
    public DocumentResponse toResponse(final Document document) {
        return new DocumentResponse(document.id(), document.owner(), document.title(), document.content());
    }
}

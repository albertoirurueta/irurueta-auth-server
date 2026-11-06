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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import com.irurueta.authserver.bff.domain.documents.Document;
import com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.model.DocumentResponse;
import org.springframework.stereotype.Component;

/**
 * Maps the model of the generated resource-server client onto the domain, so the generated types never leave this
 * adapter.
 */
@Component
public class DocumentMapper {

    /**
     * Maps a document answered by the resource server.
     *
     * @param response the document as the generated client reads it.
     * @return the domain document.
     * @throws IllegalArgumentException if the resource server answered a document that breaks the domain invariants.
     */
    public Document toDomain(final DocumentResponse response) {
        return new Document(response.getId(), response.getOwner(), response.getTitle(), response.getContent());
    }
}

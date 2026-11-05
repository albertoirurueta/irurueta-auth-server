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

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that lists documents: those of one owner, or all of them.
 */
@Service
@RequiredArgsConstructor
public class ListDocumentsUseCase {

    /** Port that provides the documents. */
    private final DocumentRepository documentRepository;

    /**
     * Lists the documents of one owner.
     *
     * @param owner subject of the owner.
     * @return the documents of the owner.
     */
    public List<Document> listOwn(final String owner) {
        return documentRepository.findByOwner(owner);
    }

    /**
     * Lists every document.
     *
     * @return all documents.
     */
    public List<Document> listAll() {
        return documentRepository.findAll();
    }
}

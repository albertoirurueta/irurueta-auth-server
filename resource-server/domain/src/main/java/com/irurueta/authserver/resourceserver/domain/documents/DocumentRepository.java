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

package com.irurueta.authserver.resourceserver.domain.documents;

import java.util.List;
import java.util.Optional;

/**
 * Port that provides and stores documents. An implementation never returns {@code null}.
 */
public interface DocumentRepository {

    /**
     * Finds the documents of one owner.
     *
     * @param owner subject of the owner.
     * @return the documents of the owner, empty when there are none.
     */
    List<Document> findByOwner(String owner);

    /**
     * Finds a document by its identifier.
     *
     * @param id identifier of the document.
     * @return the document, or an empty optional when there is none.
     */
    Optional<Document> findById(String id);

    /**
     * Finds every document.
     *
     * @return all documents, empty when there are none.
     */
    List<Document> findAll();

    /**
     * Deletes a document; does nothing when it does not exist.
     *
     * @param id identifier of the document.
     * @return {@code true} when a document was deleted.
     */
    boolean deleteById(String id);

    /**
     * Stores a document, replacing any document with the same id.
     *
     * @param document document to store.
     * @return the stored document.
     */
    Document save(Document document);
}

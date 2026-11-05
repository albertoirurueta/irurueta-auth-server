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

package com.irurueta.authserver.resourceserver.infrastructure.memory;

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/**
 * Document store kept in process memory. It starts empty and holds no demo data.
 */
@Repository
public class InMemoryDocumentRepository implements DocumentRepository {

    /** Documents by id. */
    private final Map<String, Document> documents = new ConcurrentHashMap<>();

    @Override
    public List<Document> findByOwner(final String owner) {
        return documents.values().stream().filter(document -> document.owner().equals(owner)).toList();
    }

    @Override
    public Optional<Document> findById(final String id) {
        return Optional.ofNullable(documents.get(id));
    }

    @Override
    public List<Document> findAll() {
        return List.copyOf(documents.values());
    }

    @Override
    public boolean deleteById(final String id) {
        return documents.remove(id) != null;
    }

    @Override
    public Document save(final Document document) {
        documents.put(document.id(), document);
        return document;
    }
}

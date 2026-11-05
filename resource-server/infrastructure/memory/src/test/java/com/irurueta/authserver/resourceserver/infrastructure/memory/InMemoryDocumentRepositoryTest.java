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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link InMemoryDocumentRepository}.
 */
class InMemoryDocumentRepositoryTest {

    /** First owner. */
    private static final String ALICE = "alice";

    /** Second owner. */
    private static final String BOB = "bob";

    /** Expected size when two documents are stored. */
    private static final int TWO = 2;

    /** Subject under test. */
    private final InMemoryDocumentRepository repository = new InMemoryDocumentRepository();

    /** A new repository holds no documents. */
    @Test
    void findAll_whenNewRepository_isEmpty() {
        assertTrue(repository.findAll().isEmpty());
    }

    /** Saving returns the same instance and makes it findable. */
    @Test
    void save_whenNewDocument_returnsItAndStoresIt() {
        final var document = new Document("d1", ALICE, "T", "C");

        assertSame(document, repository.save(document));
        assertEquals(1, repository.findAll().size());
    }

    /** Saving an existing id replaces the document. */
    @Test
    void save_whenIdExists_replacesDocument() {
        repository.save(new Document("d1", ALICE, "T", "C"));
        final var replacement = new Document("d1", ALICE, "New", "C");
        repository.save(replacement);

        assertEquals(List.of(replacement), repository.findAll());
    }

    /** A stored document is found by its id, and an unknown id finds nothing. */
    @Test
    void findById_whenDocumentIsStoredOrNot_findsOnlyTheStoredOne() {
        final var document = new Document("d1", ALICE, "T", "C");
        repository.save(document);

        assertEquals(document, repository.findById("d1").orElseThrow());
        assertTrue(repository.findById("missing").isEmpty());
    }

    /** Only the documents of the requested owner are returned. */
    @Test
    void findByOwner_whenSeveralOwners_returnsOnlyOwnDocuments() {
        final var own = new Document("d1", ALICE, "T", "C");
        repository.save(own);
        repository.save(new Document("d2", BOB, "T", "C"));

        assertEquals(List.of(own), repository.findByOwner(ALICE));
        assertTrue(repository.findByOwner("nobody").isEmpty());
    }

    /** Both documents are returned by findAll. */
    @Test
    void findAll_whenTwoDocuments_returnsBoth() {
        repository.save(new Document("d1", ALICE, "T", "C"));
        repository.save(new Document("d2", BOB, "T", "C"));

        assertEquals(TWO, repository.findAll().size());
    }

    /** Deleting an existing document removes it. */
    @Test
    void deleteById_whenDocumentExists_removesItAndReturnsTrue() {
        repository.save(new Document("d1", ALICE, "T", "C"));

        assertTrue(repository.deleteById("d1"));
        assertTrue(repository.findAll().isEmpty());
    }

    /** Deleting a missing document returns false. */
    @Test
    void deleteById_whenDocumentIsMissing_returnsFalse() {
        assertFalse(repository.deleteById("missing"));
    }
}

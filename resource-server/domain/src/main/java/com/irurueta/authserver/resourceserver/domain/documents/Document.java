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

/**
 * A document owned by a user.
 *
 * @param id      unique identifier of the document.
 * @param owner   subject of the user who owns the document.
 * @param title   short title of the document.
 * @param content body of the document.
 */
public record Document(String id, String owner, String title, String content) {

    /**
     * Validates the invariants of a document.
     *
     * @throws IllegalArgumentException if the id, owner or title is null or blank, or the content is null.
     */
    public Document {
        requireText(id, "id");
        requireText(owner, "owner");
        requireText(title, "title");
        if (content == null) {
            throw new IllegalArgumentException("content is required");
        }
    }

    /**
     * Rejects a null or blank value.
     *
     * @param value value to check.
     * @param name  name of the component, used in the message.
     * @throws IllegalArgumentException if the value is null or blank.
     */
    private static void requireText(final String value, final String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}

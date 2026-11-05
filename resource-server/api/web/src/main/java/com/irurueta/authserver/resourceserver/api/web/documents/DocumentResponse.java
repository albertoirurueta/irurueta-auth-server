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

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Web representation of a document.
 *
 * @param id      unique identifier of the document.
 * @param owner   subject of the user who owns the document.
 * @param title   short title of the document.
 * @param content body of the document.
 */
@Schema(description = "A document owned by a user.")
public record DocumentResponse(
        @Schema(description = "Unique identifier of the document.") String id,
        @Schema(description = "Subject of the user who owns the document.") String owner,
        @Schema(description = "Short title of the document.") String title,
        @Schema(description = "Body of the document.") String content) {
}

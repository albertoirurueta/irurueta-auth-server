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

package com.irurueta.authserver.bff.api.web.user;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Body of the response that describes the signed-in user. The JSON shape is {@code {"subject": "..."}}.
 *
 * @param subject identifier of the signed-in user.
 */
@Schema(description = "The user signed in to the BFF session")
public record SessionUserResponse(
        @Schema(description = "Identifier of the signed-in user", example = "demo-user") String subject) {
}

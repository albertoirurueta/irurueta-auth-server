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

package com.irurueta.authserver.authorization.api.web.clients;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Answer to a secret rotation. This is the only time the new secret is shown, so it is left out of
 * {@link #toString()}.
 *
 * @param clientSecret the new secret in clear text.
 */
@Schema(description = "The new client secret; it is shown only once")
public record ClientSecretResponse(String clientSecret) {

    @Override
    public String toString() {
        return "ClientSecretResponse[clientSecret=***]";
    }
}

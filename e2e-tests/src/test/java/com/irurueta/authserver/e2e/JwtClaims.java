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
package com.irurueta.authserver.e2e;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reads the claims of a JWT without verifying it: the tests only inspect what the server issued.
 */
final class JwtClaims {

    /** Position of the payload in a compact JWT. */
    private static final int PAYLOAD = 1;

    /** Mapper of the JSON of the token. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /**
     * Not instantiable.
     */
    private JwtClaims() {
    }

    /**
     * Reads the claims.
     *
     * @param jwt the compact serialization.
     * @return the claims.
     */
    static JsonNode of(final String jwt) {
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[PAYLOAD]),
                StandardCharsets.UTF_8));
    }
}

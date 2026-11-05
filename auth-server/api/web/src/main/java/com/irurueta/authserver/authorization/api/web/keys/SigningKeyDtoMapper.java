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

package com.irurueta.authserver.authorization.api.web.keys;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.SigningKeyResponse;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the signing keys of the domain onto the DTO generated from the contract, so a domain model is never returned
 * from {@link SigningKeyAdminController}. Only the public half of a key is ever mapped.
 */
@Component
public class SigningKeyDtoMapper {

    /**
     * Maps a key to its public view.
     *
     * @param key the key.
     * @return its public view, without the private half.
     */
    public SigningKeyResponse toResponse(final SigningKey key) {
        return new SigningKeyResponse(key.kid(), key.alg(), key.status().name(), key.createdAt(), key.activatedAt(),
                key.retiredAt(), key.publicJwk());
    }

    /**
     * Maps several keys, keeping their order.
     *
     * @param keys the keys.
     * @return their public views.
     */
    public List<SigningKeyResponse> toResponses(final List<SigningKey> keys) {
        return keys.stream().map(this::toResponse).toList();
    }
}

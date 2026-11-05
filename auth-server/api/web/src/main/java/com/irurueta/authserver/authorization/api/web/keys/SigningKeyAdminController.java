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

import com.irurueta.authserver.authorization.api.web.v1.generated.api.SigningKeysApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.SigningKeyResponse;
import com.irurueta.authserver.authorization.application.keys.ListSigningKeysUseCase;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration of the signing keys, as the contract {@code apis/auth-server/rest-server/auth-server-api-v1.yaml}
 * describes it through the generated {@link SigningKeysApi}. Only the public half of each key is ever returned.
 */
@RestController
@RequiredArgsConstructor
public class SigningKeyAdminController implements SigningKeysApi {

    /** Lists the keys. */
    private final ListSigningKeysUseCase listSigningKeysUseCase;

    /** Rotates the keys. */
    private final SigningKeyRotator signingKeyRotator;

    /** Maps the keys onto the generated DTO. */
    private final SigningKeyDtoMapper signingKeyDtoMapper;

    /**
     * Lists the keys.
     *
     * @return every key, without its private half.
     */
    @Override
    public ResponseEntity<List<SigningKeyResponse>> listSigningKeys() {
        return ResponseEntity.ok(signingKeyDtoMapper.toResponses(listSigningKeysUseCase.execute()));
    }

    /**
     * Rotates the keys now, whatever the age of the active key.
     *
     * @return the keys after the rotation, without their private half.
     */
    @Override
    public ResponseEntity<List<SigningKeyResponse>> rotateSigningKeys() {
        signingKeyRotator.rotateNow();
        return listSigningKeys();
    }
}

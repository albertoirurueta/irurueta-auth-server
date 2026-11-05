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

import com.irurueta.authserver.authorization.application.keys.ListSigningKeysUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration of the signing keys. Only the public half of each key is ever returned.
 */
@RestController
@RequestMapping("/api/admin/keys")
@Tag(name = "Signing keys", description = "Administration of the signing keys")
@RequiredArgsConstructor
public class SigningKeyAdminController {

    /** Lists the keys. */
    private final ListSigningKeysUseCase listSigningKeysUseCase;

    /** Rotates the keys. */
    private final SigningKeyRotator signingKeyRotator;

    /**
     * Lists the keys.
     *
     * @return every key, without its private half.
     */
    @GetMapping
    @Operation(summary = "Lists the signing keys", description = "Never exposes private key material.")
    @ApiResponse(responseCode = "200", description = "The keys")
    public List<SigningKeyResponse> list() {
        return listSigningKeysUseCase.execute().stream().map(SigningKeyResponse::from).toList();
    }

    /**
     * Rotates the keys now, whatever the age of the active key.
     *
     * @return the keys after the rotation, without their private half.
     */
    @PostMapping("/rotate")
    @Operation(summary = "Rotates the signing keys now",
            description = "Forces a rotation whatever the age of the active key: the active key is retired (it stays "
                    + "published until the tokens it signed expire), the next key becomes active and a new next key "
                    + "is generated. Keys retired for longer than the retention are deleted, and the published keys "
                    + "are refreshed. The scheduled rotation, in contrast, only rotates a key that is due.")
    @ApiResponse(responseCode = "200", description = "The keys after the rotation")
    public List<SigningKeyResponse> rotate() {
        signingKeyRotator.rotateNow();
        return list();
    }
}

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

package com.irurueta.authserver.authorization.api.web.account;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of the change password request. The passwords are left out of {@link #toString()} so they never reach a log.
 *
 * @param currentPassword the password in use.
 * @param newPassword     the password to set.
 */
@Schema(description = "Change of the password of the authenticated account")
public record ChangePasswordRequest(
        @Schema(description = "Password in use", format = "password") @NotBlank String currentPassword,
        @Schema(description = "Password to set", format = "password") @NotBlank String newPassword) {

    @Override
    public String toString() {
        return "ChangePasswordRequest[currentPassword=***, newPassword=***]";
    }
}

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
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of the registration request. The password is left out of {@link #toString()} so it never reaches a log.
 *
 * @param username desired username.
 * @param email    e-mail address that receives the verification link.
 * @param password chosen password.
 */
@Schema(description = "Registration of a new account")
public record RegisterRequest(
        @Schema(description = "Desired username") @NotBlank String username,
        @Schema(description = "E-mail address that receives the verification link") @NotBlank @Email String email,
        @Schema(description = "Chosen password", format = "password") @NotBlank String password) {

    @Override
    public String toString() {
        return "RegisterRequest[username=" + username + ", email=" + email + ", password=***]";
    }
}

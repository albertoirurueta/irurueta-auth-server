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

import com.irurueta.authserver.authorization.application.account.ChangePasswordUseCase;
import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.application.account.RequestPasswordResetUseCase;
import com.irurueta.authserver.authorization.application.account.ResetPasswordUseCase;
import com.irurueta.authserver.authorization.application.account.VerifyEmailUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Self-service account endpoints: registration, e-mail verification, password change and password reset. Failures
 * are answered as RFC 9457 problem details by {@link AccountExceptionHandler}. No answer reveals whether an e-mail
 * address belongs to an account.
 */
@RestController
@RequestMapping("/api/account")
@Tag(name = "Account", description = "Self-service account management")
@RequiredArgsConstructor
public class AccountController {

    /** Registers accounts. */
    private final RegisterAccountUseCase registerAccountUseCase;

    /** Verifies e-mail addresses. */
    private final VerifyEmailUseCase verifyEmailUseCase;

    /** Changes the password of an authenticated account. */
    private final ChangePasswordUseCase changePasswordUseCase;

    /** Sends password reset links. */
    private final RequestPasswordResetUseCase requestPasswordResetUseCase;

    /** Resets forgotten passwords. */
    private final ResetPasswordUseCase resetPasswordUseCase;

    /**
     * Registers an account. The answer is the same whether or not the address was already registered.
     *
     * @param request registration data.
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Registers an account",
            description = "The answer is the same whether or not the e-mail address is already registered.",
            security = {})
    @ApiResponse(responseCode = "202", description = "Registration accepted; an e-mail is sent")
    @ApiResponse(responseCode = "400", description = "Invalid request or rejected password",
            content = @Content(mediaType = "application/problem+json"))
    public void register(@Valid @RequestBody final RegisterRequest request) {
        registerAccountUseCase.execute(request.username(), request.email(), request.password());
    }

    /**
     * Verifies an e-mail address.
     *
     * @param token verification token received by e-mail.
     */
    @GetMapping("/verify")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Verifies an e-mail address", security = {})
    @ApiResponse(responseCode = "204", description = "E-mail address verified")
    @ApiResponse(responseCode = "400", description = "The token is invalid, expired or already used",
            content = @Content(mediaType = "application/problem+json"))
    public void verify(@RequestParam("token") final String token) {
        verifyEmailUseCase.execute(token);
    }

    /**
     * Changes the password of the authenticated account.
     *
     * @param principal authenticated account.
     * @param request   current and new passwords.
     */
    @PostMapping("/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Changes the password of the authenticated account",
            description = "Requires a bearer token issued by this server.")
    @ApiResponse(responseCode = "204", description = "Password changed")
    @ApiResponse(responseCode = "400", description = "Wrong current password or rejected new password",
            content = @Content(mediaType = "application/problem+json"))
    @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token")
    public void changePassword(final Principal principal, @Valid @RequestBody final ChangePasswordRequest request) {
        changePasswordUseCase.execute(principal.getName(), request.currentPassword(), request.newPassword());
    }

    /**
     * Asks for a password reset link. The answer is the same whether or not the address belongs to an account.
     *
     * @param request e-mail address of the account.
     */
    @PostMapping("/password/reset-request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Requests a password reset link",
            description = "The answer is the same whether or not the e-mail address belongs to an account.",
            security = {})
    @ApiResponse(responseCode = "202", description = "Request accepted; an e-mail is sent")
    @ApiResponse(responseCode = "400", description = "Invalid request",
            content = @Content(mediaType = "application/problem+json"))
    public void requestPasswordReset(@Valid @RequestBody final PasswordResetRequest request) {
        requestPasswordResetUseCase.execute(request.email());
    }

    /**
     * Resets a forgotten password.
     *
     * @param request reset token and new password.
     */
    @PostMapping("/password/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Resets a forgotten password", security = {})
    @ApiResponse(responseCode = "204", description = "Password reset")
    @ApiResponse(responseCode = "400", description = "Invalid token or rejected password",
            content = @Content(mediaType = "application/problem+json"))
    public void resetPassword(@Valid @RequestBody final ResetPasswordRequest request) {
        resetPasswordUseCase.execute(request.token(), request.newPassword());
    }
}

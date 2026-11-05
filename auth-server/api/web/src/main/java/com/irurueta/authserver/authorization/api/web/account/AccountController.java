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

import com.irurueta.authserver.authorization.api.web.v1.generated.api.AccountApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ChangePasswordRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.PasswordResetRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.RegisterRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ResetPasswordRequest;
import com.irurueta.authserver.authorization.application.account.ChangePasswordUseCase;
import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.application.account.RequestPasswordResetUseCase;
import com.irurueta.authserver.authorization.application.account.ResetPasswordUseCase;
import com.irurueta.authserver.authorization.application.account.VerifyEmailUseCase;
import com.irurueta.authserver.authorization.domain.account.AccountMailException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Self-service account endpoints: registration, e-mail verification, password change and password reset. The paths,
 * status codes and bodies are those of the contract {@code apis/auth-server/rest-server/auth-server-api-v1.yaml},
 * through the generated {@link AccountApi}. Failures are answered as RFC 9457 problem details by
 * {@link AccountExceptionHandler}. No answer reveals whether an e-mail address belongs to an account.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class AccountController implements AccountApi {

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

    /** Limits the unauthenticated requests per client and per e-mail address. */
    private final AccountRateLimiter accountRateLimiter;

    /**
     * Registers an account. The answer is the same whether or not the address or the username was already taken.
     *
     * @param request registration data.
     * @return {@code 202 Accepted}.
     */
    @Override
    public ResponseEntity<Void> register(final RegisterRequest request) {
        accountRateLimiter.check(clientAddress(), request.email());
        registerAccountUseCase.execute(request.username(), request.email(), request.password());
        return ResponseEntity.accepted().build();
    }

    /**
     * Verifies an e-mail address.
     *
     * @param token verification token received by e-mail.
     * @return {@code 204 No Content}.
     */
    @Override
    public ResponseEntity<Void> verify(final String token) {
        accountRateLimiter.check(clientAddress(), null);
        verifyEmailUseCase.execute(token);
        return ResponseEntity.noContent().build();
    }

    /**
     * Changes the password of the authenticated account, the principal of the bearer token.
     *
     * @param request current and new passwords.
     * @return {@code 204 No Content}.
     */
    @Override
    public ResponseEntity<Void> changePassword(final ChangePasswordRequest request) {
        final var principal = currentRequest().getUserPrincipal();
        changePasswordUseCase.execute(principal.getName(), request.currentPassword(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    /**
     * Asks for a password reset link. The answer is the same whether or not the address belongs to an account, and
     * even when the link cannot be delivered: only a registered address is ever mailed, so a delivery failure must
     * not tell the caller that the address is registered (the use case has rolled back its token by then).
     *
     * @param request e-mail address of the account.
     * @return {@code 202 Accepted}.
     */
    @Override
    public ResponseEntity<Void> requestPasswordReset(final PasswordResetRequest request) {
        accountRateLimiter.check(clientAddress(), request.email());
        try {
            requestPasswordResetUseCase.execute(request.email());
        } catch (final AccountMailException e) {
            log.warn("A password reset link could not be delivered: {}", e.getMessage());
        }
        return ResponseEntity.accepted().build();
    }

    /**
     * Resets a forgotten password.
     *
     * @param request reset token and new password.
     * @return {@code 204 No Content}.
     */
    @Override
    public ResponseEntity<Void> resetPassword(final ResetPasswordRequest request) {
        accountRateLimiter.check(clientAddress(), null);
        resetPasswordUseCase.execute(request.token(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    /**
     * Returns the address of the client making the current request, the key of the rate limit. The generated
     * interface carries only the contract's parameters, so the request is taken from the request context.
     *
     * @return the client address.
     */
    private static String clientAddress() {
        return currentRequest().getRemoteAddr();
    }

    /**
     * Returns the request being handled.
     *
     * @return the current HTTP request.
     */
    private static HttpServletRequest currentRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
    }
}

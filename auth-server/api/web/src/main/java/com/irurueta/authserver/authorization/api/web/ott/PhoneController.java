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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.api.web.v1.generated.api.PhoneApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.PhoneEnrolmentResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.PhoneResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.StartPhoneEnrolmentRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.VerifyPhoneRequest;
import com.irurueta.authserver.authorization.application.sms.ConfirmPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.FindUserPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.RemovePhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.StartPhoneEnrolmentUseCase;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Shows, enrols, verifies and removes the phone number of the authenticated account, the number the SMS codes go to.
 * The paths, status codes and bodies are those of the contract {@code apis/auth-server/rest-server/
 * auth-server-api-v1.yaml}, through the generated {@link PhoneApi}; failures are answered by
 * {@link OttExceptionHandler}. Starting an enrolment and verifying it spend SMS budget and guess a code, so both are
 * limited per client address and per account ({@link OttRateLimiter}). Starting an enrolment (which may replace the
 * verified phone, a second factor) and removing the phone need a recent multi-factor sign-in while the account has a
 * confirmed second factor ({@link StepUpGuard}).
 */
@RestController
@RequiredArgsConstructor
public class PhoneController implements PhoneApi {

    /** Prefix of the rate-limit key of an account, which cannot clash with a user name typed in a sign-in form. */
    static final String ACCOUNT_KEY_PREFIX = "phone:";

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Finds the verified phone of the account. */
    private final FindUserPhoneUseCase findUserPhoneUseCase;

    /** Starts an enrolment. */
    private final StartPhoneEnrolmentUseCase startPhoneEnrolmentUseCase;

    /** Confirms an enrolment. */
    private final ConfirmPhoneUseCase confirmPhoneUseCase;

    /** Removes the phone. */
    private final RemovePhoneUseCase removePhoneUseCase;

    /** Requires a recent multi-factor sign-in before the phone is replaced or removed. */
    private final StepUpGuard stepUpGuard;

    /** Limits the requests. */
    private final OttRateLimiter rateLimiter;

    /** Maps the results onto the contract's DTOs. */
    private final PhoneDtoMapper phoneDtoMapper;

    /** The current request, injected as a thread-bound proxy, which tells the address of the client. */
    private final HttpServletRequest request;

    /**
     * Gets the verified phone, masked.
     *
     * @return {@code 200 OK} with the phone.
     * @throws PhoneNotFoundException if the account has no verified phone.
     */
    @Override
    public ResponseEntity<PhoneResponse> getPhone() {
        final var account = currentAccountResolver.resolve();
        final var phone = findUserPhoneUseCase.execute(account.id()).orElseThrow(PhoneNotFoundException::new);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(phoneDtoMapper.toResponse(phone));
    }

    /**
     * Starts the enrolment of a phone: a verification code is sent by SMS.
     *
     * @param startPhoneEnrolmentRequest the number.
     * @return {@code 202 Accepted} with how long the code stays valid.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException if the account
     *         has a confirmed second factor and the token does not show a recent multi-factor sign-in.
     * @throws OttRateLimitExceededException if the client or the account asked too many times.
     */
    @Override
    public ResponseEntity<PhoneEnrolmentResponse> startPhoneEnrolment(
            final StartPhoneEnrolmentRequest startPhoneEnrolmentRequest) {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        rateLimiter.checkGeneration(request.getRemoteAddr(), ACCOUNT_KEY_PREFIX + account.id());
        final var started = startPhoneEnrolmentUseCase.execute(account.id(), startPhoneEnrolmentRequest.phone());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(phoneDtoMapper.toResponse(started));
    }

    /**
     * Confirms the phone with the code received by SMS.
     *
     * @param verifyPhoneRequest the code.
     * @return {@code 200 OK} with the verified phone.
     * @throws InvalidPhoneCodeException     if the code is not valid.
     * @throws OttRateLimitExceededException if the client or the account tried too many times.
     */
    @Override
    public ResponseEntity<PhoneResponse> verifyPhone(final VerifyPhoneRequest verifyPhoneRequest) {
        final var account = currentAccountResolver.resolve();
        rateLimiter.checkVerification(request.getRemoteAddr(), ACCOUNT_KEY_PREFIX + account.id());
        if (!confirmPhoneUseCase.execute(account.id(), account.username(), verifyPhoneRequest.code())) {
            throw new InvalidPhoneCodeException();
        }
        final var phone = findUserPhoneUseCase.execute(account.id()).orElseThrow(PhoneNotFoundException::new);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(phoneDtoMapper.toResponse(phone));
    }

    /**
     * Removes the phone and any pending verification.
     *
     * @return {@code 204 No Content}.
     * @throws com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException if the token
     *         does not show a recent multi-factor sign-in.
     */
    @Override
    public ResponseEntity<Void> removePhone() {
        final var account = currentAccountResolver.resolve();
        stepUpGuard.requireRecentMultiFactor(account.id());
        removePhoneUseCase.execute(account.id(), account.username());
        return ResponseEntity.noContent().build();
    }
}

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
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.PhonePageApi;
import com.irurueta.authserver.authorization.application.sms.ConfirmPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.FindUserPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.InvalidPhoneNumberException;
import com.irurueta.authserver.authorization.application.sms.RemovePhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import com.irurueta.authserver.authorization.application.sms.StartPhoneEnrolmentUseCase;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.HashMap;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;

// tag::phone-page-controller[]
/**
 * Serves the phone account page and the session-protected form posts it uses, as the contract
 * {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes them through the generated
 * {@link PhonePageApi}. A browser page has a session, not a bearer token, so it cannot call the REST API
 * ({@code /api/account/phone}, which {@code ApiSecurityConfig} keeps bearer-only); the forms call the same use cases
 * instead, with the same limits, and each answers by redirecting back to the page (post/redirect/get) with the outcome
 * in the {@code status} parameter. The number is shown masked, as the REST API answers it.
 */
@Controller
@RequiredArgsConstructor
public class PhonePageController implements PhonePageApi {

    /** Path of the page, taken from the contract. */
    public static final String PHONE_PATH = PATH_PHONE_PAGE;

    /** Name of the template of the page. */
    static final String VIEW_NAME = "account-phone";

    /** Name of the model attribute that holds the masked verified number, absent when there is none. */
    static final String PHONE_ATTRIBUTE = "phone";

    /** Name of the model attribute that holds the outcome of the previous post. */
    static final String STATUS_ATTRIBUTE = "status";

    /** Status of a code that was requested. */
    static final String PENDING = "pending";

    /** Status of a number that was verified. */
    static final String VERIFIED = "verified";

    /** Status of a number that was removed. */
    static final String REMOVED = "removed";

    /** Status of a number that is not valid. */
    static final String INVALID_PHONE = "invalid-phone";

    /** Status of a number of a country SMS messages are not sent to. */
    static final String COUNTRY_NOT_ALLOWED = "country-not-allowed";

    /** Status of a wrong code. */
    static final String INVALID_CODE = "invalid-code";

    /** Status of a request over a limit. */
    static final String RATE_LIMITED = "rate-limited";

    /** Status of a removal that needs a recent multi-factor sign-in. */
    static final String STEP_UP_REQUIRED = "step-up-required";

    /** The statuses the page tells; any other value of the parameter is ignored. */
    private static final Set<String> STATUSES = Set.of(PENDING, VERIFIED, REMOVED, INVALID_PHONE,
            COUNTRY_NOT_ALLOWED, INVALID_CODE, RATE_LIMITED, STEP_UP_REQUIRED);

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

    /** Requires a recent multi-factor sign-in before the phone is removed. */
    private final PhoneSessionStepUp stepUp;

    /** Limits the requests. */
    private final OttRateLimiter rateLimiter;

    /** Maps the phone onto its masked form. */
    private final PhoneDtoMapper phoneDtoMapper;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, which tells the address of the client. */
    private final HttpServletRequest request;

    /**
     * Renders the page.
     *
     * @param status outcome of the previous post, ignored when it is not one of the known ones.
     * @return the page, never cached.
     */
    @Override
    public ResponseEntity<String> phonePage(final String status) {
        final var account = currentAccountResolver.resolve();
        final var model = new HashMap<String, Object>();
        findUserPhoneUseCase.execute(account.id())
                .ifPresent(phone -> model.put(PHONE_ATTRIBUTE, phoneDtoMapper.toResponse(phone).maskedNumber()));
        if (status != null && STATUSES.contains(status)) {
            model.put(STATUS_ATTRIBUTE, status);
        }
        final var page = pageRenderer.render(VIEW_NAME, model);
        return ResponseEntity.status(page.getStatusCode())
                .headers(page.getHeaders())
                .cacheControl(CacheControl.noStore())
                .body(page.getBody());
    }

    /**
     * Sends the verification code to the number.
     *
     * @param phone the number.
     * @return a redirect to the page; the status is {@code pending} whether or not the number belongs to another
     *         account.
     */
    @Override
    public ResponseEntity<Void> startPhoneEnrolmentPage(final String phone) {
        final var account = currentAccountResolver.resolve();
        try {
            rateLimiter.checkGeneration(request.getRemoteAddr(), PhoneController.ACCOUNT_KEY_PREFIX + account.id());
            startPhoneEnrolmentUseCase.execute(account.id(), phone);
            return redirect(PENDING);
        } catch (final OttRateLimitExceededException e) {
            return redirect(RATE_LIMITED);
        } catch (final InvalidPhoneNumberException e) {
            return redirect(INVALID_PHONE);
        } catch (final SmsCountryNotAllowedException e) {
            return redirect(COUNTRY_NOT_ALLOWED);
        }
    }

    /**
     * Confirms the number with the code.
     *
     * @param code the code received by SMS.
     * @return a redirect to the page, with the outcome.
     */
    @Override
    public ResponseEntity<Void> verifyPhonePage(final String code) {
        final var account = currentAccountResolver.resolve();
        try {
            rateLimiter.checkVerification(request.getRemoteAddr(), PhoneController.ACCOUNT_KEY_PREFIX + account.id());
        } catch (final OttRateLimitExceededException e) {
            return redirect(RATE_LIMITED);
        }
        return redirect(confirmPhoneUseCase.execute(account.id(), code) ? VERIFIED : INVALID_CODE);
    }

    /**
     * Removes the phone, when the session shows a recent enough multi-factor sign-in.
     *
     * @return a redirect to the page, with the outcome.
     */
    @Override
    public ResponseEntity<Void> removePhonePage() {
        final var account = currentAccountResolver.resolve();
        if (!stepUp.isSatisfied(account.id(), SecurityContextHolder.getContext().getAuthentication())) {
            return redirect(STEP_UP_REQUIRED);
        }
        removePhoneUseCase.execute(account.id());
        return redirect(REMOVED);
    }

    /**
     * Builds the redirect back to the page.
     *
     * @param status the outcome.
     * @return {@code 303 See Other} to the page.
     */
    private ResponseEntity<Void> redirect(final String status) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, URI.create(PHONE_PATH + "?" + STATUS_ATTRIBUTE + "=" + status).toString())
                .build();
    }
}
// end::phone-page-controller[]

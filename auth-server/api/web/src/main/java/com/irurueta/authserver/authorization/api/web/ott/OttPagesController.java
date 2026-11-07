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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;

/**
 * Serves the two pages of the one-time token flow, as the contract {@code apis/auth-server/web-pages/
 * auth-server-pages-v1.yaml} describes them through the generated {@link OneTimeTokenPageApi}: the page where the code
 * is entered (or that says to check the inbox when a magic link was requested) and the page a magic link opens, whose
 * button posts the token. What the first one shows comes from the pending token of the session (see
 * {@link PendingOtt}), so it is the same page whatever identifier was typed.
 */
@Controller
@RequiredArgsConstructor
public class OttPagesController implements OneTimeTokenPageApi {

    /** Path of the page where the code is entered, taken from the contract. */
    public static final String OTT_CODE_PATH = PATH_OTT_CODE_PAGE;

    /** Name of the template of the page where the code is entered. */
    static final String CODE_VIEW_NAME = "ott-code";

    /** Name of the template of the confirmation page. */
    static final String CONFIRM_VIEW_NAME = "ott-confirm";

    /** Name of the model attribute that tells whether this browser has asked for a token. */
    static final String PENDING_ATTRIBUTE = "pending";

    /** Name of the model attribute that holds the kind of token, {@code code} or {@code link}. */
    static final String KIND_ATTRIBUTE = "kind";

    /** Name of the model attribute that holds the channel, {@code email} or {@code sms}. */
    static final String CHANNEL_ATTRIBUTE = "channel";

    /** Name of the model attribute that holds the purpose, {@code login} or {@code second-factor}. */
    static final String PURPOSE_ATTRIBUTE = "purpose";

    /** Name of the model attribute that holds the path the code form posts to. */
    static final String POST_PATH_ATTRIBUTE = "postPath";

    /** Name of the model attribute that holds the name of the form field of the code. */
    static final String CODE_FIELD_ATTRIBUTE = "codeField";

    /** Name of the model attribute that holds the path a new token is requested at. */
    static final String GENERATE_PATH_ATTRIBUTE = "generatePath";

    /** Name of the model attribute that holds the key of the message of a failed attempt. */
    static final String ERROR_MESSAGE_ATTRIBUTE = "errorMessageKey";

    /** Name of the model attribute that holds the token of the magic link. */
    static final String TOKEN_ATTRIBUTE = "token";

    /** Key of the message shown when a code is wrong. */
    static final String GENERIC_ERROR = "ott.error.generic";

    /** Key of the message shown when the second factor is locked. */
    static final String LOCKED_ERROR = "ott.error.locked";

    /** Value of the purpose attribute of a sign-in. */
    static final String LOGIN_VALUE = "login";

    /** Value of the kind attribute of a numeric code. */
    static final String CODE_VALUE = "code";

    /** Name of the header that tells browsers to send no referrer. */
    static final String REFERRER_POLICY = "Referrer-Policy";

    /** Renders the pages. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, whose session holds the pending token. */
    private final HttpServletRequest request;

    /**
     * Renders the page where the code is entered.
     *
     * @param error present (even if empty) when the previous attempt failed.
     * @return the page.
     */
    @Override
    public ResponseEntity<String> ottCodePage(final String error) {
        final var pending = PendingOtt.of(request);
        final var secondFactor = pending.map(PendingOtt::purpose).filter(OttPurpose.SECOND_FACTOR::equals).isPresent();
        final var model = new HashMap<String, Object>();
        model.put(PENDING_ATTRIBUTE, pending.isPresent());
        model.put(KIND_ATTRIBUTE, pending.map(token -> lowerCase(token.kind().name())).orElse(CODE_VALUE));
        model.put(CHANNEL_ATTRIBUTE, pending.map(token -> lowerCase(token.channel().name()))
                .orElse(lowerCase(OttChannel.EMAIL.name())));
        model.put(PURPOSE_ATTRIBUTE, secondFactor ? OttGenerationParameters.SECOND_FACTOR_VALUE : LOGIN_VALUE);
        model.put(POST_PATH_ATTRIBUTE, secondFactor ? OttSecondFactorFilter.SECOND_FACTOR_OTT_PATH : OTT_CODE_PATH);
        model.put(CODE_FIELD_ATTRIBUTE, secondFactor ? OttSecondFactorFilter.CODE_PARAMETER
                : OttAuthenticationConverter.TOKEN_PARAMETER);
        model.put(GENERATE_PATH_ATTRIBUTE, OttRateLimitFilter.GENERATE_PATH);
        if (error != null) {
            model.put(ERROR_MESSAGE_ATTRIBUTE, lastFailureWasLockout() ? LOCKED_ERROR : GENERIC_ERROR);
        }
        return pageRenderer.render(CODE_VIEW_NAME, model);
    }

    /**
     * Renders the page a magic link opens. It is never cached and a browser sends no referrer from it, because the
     * token is in its address.
     *
     * @param token the token of the link, which is only posted back, never checked here.
     * @return the confirmation page.
     */
    @Override
    public ResponseEntity<String> ottConfirmPage(final String token) {
        final var page = pageRenderer.render(CONFIRM_VIEW_NAME, Map.of(
                TOKEN_ATTRIBUTE, token,
                POST_PATH_ATTRIBUTE, OTT_CODE_PATH,
                CODE_FIELD_ATTRIBUTE, OttAuthenticationConverter.TOKEN_PARAMETER));
        return ResponseEntity.status(page.getStatusCode())
                .headers(page.getHeaders())
                .cacheControl(CacheControl.noStore())
                .header(REFERRER_POLICY, "no-referrer")
                .body(page.getBody());
    }

    /**
     * Tells whether the previous attempt failed because the second factor is locked, which Spring Security keeps in
     * the session.
     *
     * @return {@code true} when the session holds a {@link LockedException} as the last failure.
     */
    private boolean lastFailureWasLockout() {
        final var session = request.getSession(false);
        final var failure = session == null ? null : session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        return failure instanceof LockedException;
    }

    /**
     * Lower-cases a name, whatever the platform's locale is.
     *
     * @param name the name.
     * @return the name in lower case.
     */
    private static String lowerCase(final String name) {
        return name.toLowerCase(Locale.ROOT);
    }
}

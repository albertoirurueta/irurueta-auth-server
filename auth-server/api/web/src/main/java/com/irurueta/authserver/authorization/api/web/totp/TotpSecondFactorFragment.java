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

package com.irurueta.authserver.authorization.api.web.totp;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorFragment;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.totp.CountRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.application.totp.EnrollTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.IsTotpEnabledUseCase;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

// tag::totp-second-factor-fragment[]
/**
 * Contributes the TOTP forms to the second-factor page, as every second factor does through the
 * {@link SecondFactorFragment} extension point. What the fragment shows depends on the signed-in user:
 *
 * <ul>
 *   <li>without a confirmed authenticator app but with another confirmed second factor (for example a passkey),
 *       nothing: that factor completes the sign-in, so no secret is generated and no enrolment is offered;</li>
 *   <li>without any confirmed second factor, the enrolment form: a new secret is generated (replacing any pending
 *       one), shown as a QR code and as its {@code otpauth} URI, and the first code confirms it;</li>
 *   <li>with one, the form of its code and the recovery-code form, plus a warning when
 *       {@value CountRecoveryCodesUseCase#LOW_THRESHOLD} or fewer recovery codes are left.</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class TotpSecondFactorFragment implements SecondFactorFragment {

    /** Position of the TOTP forms in the second-factor page. */
    public static final int ORDER = 100;

    /** Model attribute telling the fragment to show anything at all. */
    public static final String OFFERED_ATTRIBUTE = "totpOffered";

    /** Model attribute telling the fragment to show the enrolment form. */
    public static final String ENROLMENT_ATTRIBUTE = "totpEnrolment";

    /** Model attribute with the {@code otpauth} URI of the enrolment. */
    public static final String OTPAUTH_URI_ATTRIBUTE = "totpOtpauthUri";

    /** Model attribute with the QR code of the enrolment, as a {@code data:} URI. */
    public static final String QR_CODE_ATTRIBUTE = "totpQrCode";

    /** Model attribute with the number of unused recovery codes. */
    public static final String CODES_LEFT_ATTRIBUTE = "totpRecoveryCodesLeft";

    /** Model attribute telling the fragment to warn that few recovery codes are left. */
    public static final String CODES_LOW_ATTRIBUTE = "totpRecoveryCodesLow";

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Tells whether the user has a confirmed authenticator app. */
    private final IsTotpEnabledUseCase isTotpEnabledUseCase;

    /** Tells whether the user has confirmed another second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Starts an enrolment. */
    private final EnrollTotpUseCase enrollTotpUseCase;

    /** Counts the unused recovery codes. */
    private final CountRecoveryCodesUseCase countRecoveryCodesUseCase;

    /** Renders the enrolment URI as a QR code. */
    private final QrCodeRenderer qrCodeRenderer;

    @Override
    public String templateName() {
        return "totp";
    }

    @Override
    public String fragmentName() {
        return "form";
    }

    @Override
    public int order() {
        return ORDER;
    }

    /**
     * Supplies the enrolment (a new pending secret) to a user without any confirmed second factor, the number of
     * recovery codes left to a user with a confirmed authenticator app, and hides the forms from a user whose only
     * confirmed second factors are other ones.
     *
     * @param authentication the authentication of the user the page is rendered for.
     * @return the model attributes; none when nobody is signed in.
     */
    @Override
    public Map<String, Object> modelAttributes(final Authentication authentication) {
        if (!MfaAuthorizationManager.isUser(authentication)) {
            return Map.of();
        }
        final var username = authentication.getName();
        final var userId = userResolver.userIdOf(username);
        if (!isTotpEnabledUseCase.execute(userId)) {
            if (hasConfirmedSecondFactorUseCase.execute(userId)) {
                return Map.of(OFFERED_ATTRIBUTE, false);
            }
            final var otpauthUri = enrollTotpUseCase.execute(userId, username);
            return Map.of(OFFERED_ATTRIBUTE, true, ENROLMENT_ATTRIBUTE, true, OTPAUTH_URI_ATTRIBUTE, otpauthUri,
                    QR_CODE_ATTRIBUTE, qrCodeRenderer.render(otpauthUri));
        }
        final var left = countRecoveryCodesUseCase.execute(userId);
        return Map.of(OFFERED_ATTRIBUTE, true, ENROLMENT_ATTRIBUTE, false, CODES_LEFT_ATTRIBUTE, left,
                CODES_LOW_ATTRIBUTE, left <= CountRecoveryCodesUseCase.LOW_THRESHOLD);
    }
}
// end::totp-second-factor-fragment[]

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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.FactorGrantedAuthority;

// tag::ott-factors[]
/**
 * Registers the one-time token methods as authentication factors. One authority cannot carry two strengths and the
 * registry refuses two factors with the same authority, so each use of each channel is a factor of its own: the
 * e-mail code or magic link as a sign-in ({@code FACTOR_OTT}, Spring Security's own constant) and the SMS code as a
 * sign-in are {@link FactorStrength#PRIMARY} (they prove the possession of a mailbox or a phone, which is as strong as
 * a password and no more), and the same two as the second factor of a user who already signed in with a primary
 * factor are {@link FactorStrength#SECOND}. The {@code amr} values are those of RFC 8176: {@code otp} for the code or
 * the link sent by e-mail and {@code sms} for the code sent by SMS.
 */
@Configuration(proxyBeanMethods = false)
public class OttFactors {

    /** RFC 8176 {@code amr} value of a one-time password sent by e-mail. */
    public static final String EMAIL_AMR_VALUE = "otp";

    /** RFC 8176 {@code amr} value of a one-time password sent by SMS. */
    public static final String SMS_AMR_VALUE = "sms";

    /** Authority of the e-mail code or magic link as a sign-in. */
    public static final String EMAIL_AUTHORITY = FactorGrantedAuthority.OTT_AUTHORITY;

    /** Authority of the SMS code as a sign-in. */
    public static final String SMS_AUTHORITY = "FACTOR_OTT_SMS";

    /** Authority of the e-mail code or magic link as a second factor. */
    public static final String EMAIL_SECOND_FACTOR_AUTHORITY = "FACTOR_OTT_EMAIL_2FA";

    /** Authority of the SMS code as a second factor. */
    public static final String SMS_SECOND_FACTOR_AUTHORITY = "FACTOR_OTT_SMS_2FA";

    /**
     * Declares the e-mail code and magic link as a sign-in.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor ottEmailAuthenticationFactor() {
        return new AuthenticationFactor("ott-email", EMAIL_AMR_VALUE, EMAIL_AUTHORITY, FactorStrength.PRIMARY);
    }

    /**
     * Declares the SMS code as a sign-in.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor ottSmsAuthenticationFactor() {
        return new AuthenticationFactor("ott-sms", SMS_AMR_VALUE, SMS_AUTHORITY, FactorStrength.PRIMARY);
    }

    /**
     * Declares the e-mail code and magic link as a second factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor ottEmailSecondAuthenticationFactor() {
        return new AuthenticationFactor("ott-email-2fa", EMAIL_AMR_VALUE, EMAIL_SECOND_FACTOR_AUTHORITY,
                FactorStrength.SECOND);
    }

    /**
     * Declares the SMS code as a second factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor ottSmsSecondAuthenticationFactor() {
        return new AuthenticationFactor("ott-sms-2fa", SMS_AMR_VALUE, SMS_SECOND_FACTOR_AUTHORITY,
                FactorStrength.SECOND);
    }
    // end::ott-factors[]

    /**
     * Gets the authority a channel grants when it signs the user in.
     *
     * @param channel the channel the token was delivered through.
     * @return {@link #EMAIL_AUTHORITY} or {@link #SMS_AUTHORITY}.
     */
    public static String signInAuthority(final OttChannel channel) {
        return switch (channel) {
            case EMAIL -> EMAIL_AUTHORITY;
            case SMS -> SMS_AUTHORITY;
        };
    }

    /**
     * Gets the authority a channel grants when it is the second factor.
     *
     * @param channel the channel the token was delivered through.
     * @return {@link #EMAIL_SECOND_FACTOR_AUTHORITY} or {@link #SMS_SECOND_FACTOR_AUTHORITY}.
     */
    public static String secondFactorAuthority(final OttChannel channel) {
        return switch (channel) {
            case EMAIL -> EMAIL_SECOND_FACTOR_AUTHORITY;
            case SMS -> SMS_SECOND_FACTOR_AUTHORITY;
        };
    }
}

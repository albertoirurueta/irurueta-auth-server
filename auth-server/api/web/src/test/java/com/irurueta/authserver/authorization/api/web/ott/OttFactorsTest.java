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

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/** Unit tests of {@link OttFactors}. */
class OttFactorsTest {

    /** Configuration under test. */
    private final OttFactors factors = new OttFactors();

    /** The e-mail sign-in is a primary factor on Spring's constant, reported as otp. */
    @Test
    void ottEmailAuthenticationFactor_whenCalled_isAPrimaryOtpFactor() {
        assertEquals(new AuthenticationFactor("ott-email", "otp", FactorGrantedAuthority.OTT_AUTHORITY,
                FactorStrength.PRIMARY), factors.ottEmailAuthenticationFactor());
    }

    /** The SMS sign-in is a primary factor reported as sms. */
    @Test
    void ottSmsAuthenticationFactor_whenCalled_isAPrimarySmsFactor() {
        assertEquals(new AuthenticationFactor("ott-sms", "sms", "FACTOR_OTT_SMS", FactorStrength.PRIMARY),
                factors.ottSmsAuthenticationFactor());
    }

    /** The e-mail second factor is a second factor reported as otp. */
    @Test
    void ottEmailSecondAuthenticationFactor_whenCalled_isASecondOtpFactor() {
        assertEquals(new AuthenticationFactor("ott-email-2fa", "otp", "FACTOR_OTT_EMAIL_2FA", FactorStrength.SECOND),
                factors.ottEmailSecondAuthenticationFactor());
    }

    /** The SMS second factor is a second factor reported as sms. */
    @Test
    void ottSmsSecondAuthenticationFactor_whenCalled_isASecondSmsFactor() {
        assertEquals(new AuthenticationFactor("ott-sms-2fa", "sms", "FACTOR_OTT_SMS_2FA", FactorStrength.SECOND),
                factors.ottSmsSecondAuthenticationFactor());
    }

    /** The sign-in authority depends on the channel. */
    @Test
    void signInAuthority_whenGivenAChannel_isTheAuthorityOfTheChannel() {
        assertEquals("FACTOR_OTT", OttFactors.signInAuthority(OttChannel.EMAIL));
        assertEquals("FACTOR_OTT_SMS", OttFactors.signInAuthority(OttChannel.SMS));
    }

    /** The second-factor authority depends on the channel. */
    @Test
    void secondFactorAuthority_whenGivenAChannel_isTheAuthorityOfTheChannel() {
        assertEquals("FACTOR_OTT_EMAIL_2FA", OttFactors.secondFactorAuthority(OttChannel.EMAIL));
        assertEquals("FACTOR_OTT_SMS_2FA", OttFactors.secondFactorAuthority(OttChannel.SMS));
    }
}

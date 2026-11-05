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

package com.irurueta.authserver.authorization.application.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.domain.keys.SignedTokenLifetimes;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SigningKeyRetention}.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyRetentionTest {

    /** Clock skew used by the tests. */
    private static final Duration SKEW = Duration.ofMinutes(1);

    /** Number of days of a configured retention longer than every token lifetime. */
    private static final long LONG_RETENTION_DAYS = 7;

    /** Number of minutes of a short client token lifetime. */
    private static final long SHORT_TOKEN_MINUTES = 10;

    /** Number of hours of a client token lifetime longer than the e-mail verification tokens. */
    private static final long LONG_TOKEN_HOURS = 48;

    /** Port that reports the lifetimes of the client tokens. */
    @Mock
    private SignedTokenLifetimes signedTokenLifetimes;

    /**
     * Verifies that a configured retention longer than every token lifetime is used as it is.
     */
    @Test
    void effective_whenConfiguredRetentionIsLonger_returnsTheConfiguredRetention() {
        when(signedTokenLifetimes.longest()).thenReturn(Duration.ofMinutes(SHORT_TOKEN_MINUTES));
        final var configured = Duration.ofDays(LONG_RETENTION_DAYS);

        assertEquals(configured, new SigningKeyRetention(signedTokenLifetimes, configured, SKEW).effective());
    }

    /**
     * Verifies that the e-mail verification tokens, signed with the same keys, keep a retired key published for
     * their whole lifetime plus the skew, even with a short configured retention and short client tokens.
     */
    @Test
    void effective_whenVerificationTokensLiveLongest_coversThemPlusTheSkew() {
        when(signedTokenLifetimes.longest()).thenReturn(Duration.ofMinutes(SHORT_TOKEN_MINUTES));

        assertEquals(RegisterAccountUseCase.VERIFICATION_TTL.plus(SKEW),
                new SigningKeyRetention(signedTokenLifetimes, Duration.ofHours(2), SKEW).effective());
    }

    /**
     * Verifies that a client whose tokens outlive everything else lengthens the retention to its lifetime plus the
     * skew.
     */
    @Test
    void effective_whenAClientTokenLivesLongest_coversItPlusTheSkew() {
        final var longest = Duration.ofHours(LONG_TOKEN_HOURS);
        when(signedTokenLifetimes.longest()).thenReturn(longest);

        assertEquals(longest.plus(SKEW),
                new SigningKeyRetention(signedTokenLifetimes, Duration.ofHours(2), SKEW).effective());
    }
}

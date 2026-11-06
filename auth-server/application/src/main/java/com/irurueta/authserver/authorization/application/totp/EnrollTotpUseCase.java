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

package com.irurueta.authserver.authorization.application.totp;

import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.totp.SecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import com.irurueta.authserver.authorization.domain.totp.TotpUri;
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that starts the enrolment of an authenticator app: it generates a secret, stores it encrypted and
 * unconfirmed (replacing any earlier unconfirmed one) and returns the {@code otpauth://} URI to show as a QR code.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class EnrollTotpUseCase {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /** Port that encrypts the secrets at rest. */
    private final TotpSecretCipher totpSecretCipher;

    /** Generator of the shared secrets. */
    private final SecretGenerator secretGenerator;

    /** Source of the current time. */
    private final Clock clock;

    /** Multi-factor settings: the issuer shown by the authenticator app. */
    private final MfaProperties mfaProperties;

    /**
     * Starts the enrolment.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, shown by the authenticator app.
     * @return the {@code otpauth://} URI.
     * @throws TotpAlreadyEnabledException if the user already confirmed an authenticator app.
     */
    public String execute(final UUID userId, final String username) {
        if (totpCredentialRepository.findByUser(userId).filter(TotpCredential::confirmed).isPresent()) {
            throw new TotpAlreadyEnabledException("An authenticator app is already enabled");
        }
        final var secret = secretGenerator.generate();
        totpCredentialRepository.save(new TotpCredential(
                userId, totpSecretCipher.encrypt(secret), false, TotpCredential.NEVER_USED, clock.instant()));
        return TotpUri.build(mfaProperties.totpIssuer(), username, secret);
    }
}

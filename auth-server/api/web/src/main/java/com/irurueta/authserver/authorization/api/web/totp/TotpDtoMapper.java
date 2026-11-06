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

import com.irurueta.authserver.authorization.api.web.v1.generated.model.RecoveryCodesResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.TotpEnrollmentResponse;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the results of the authenticator app and recovery code use cases onto the DTOs generated from the contract.
 */
@Component
public class TotpDtoMapper {

    /**
     * Maps a pending enrolment.
     *
     * @param otpauthUri the {@code otpauth://} URI that carries the secret.
     * @param qrCode     the URI as a QR code, in a {@code data:} URI.
     * @return the answer to the enrolment.
     */
    public TotpEnrollmentResponse toEnrollmentResponse(final String otpauthUri, final String qrCode) {
        return new TotpEnrollmentResponse(otpauthUri, qrCode);
    }

    /**
     * Maps a freshly generated set of recovery codes; all of them are unused.
     *
     * @param codes the codes in clear text.
     * @return the answer, whose {@code remaining} is the size of the set.
     */
    public RecoveryCodesResponse toRecoveryCodesResponse(final List<String> codes) {
        return new RecoveryCodesResponse(codes, codes.size());
    }
}

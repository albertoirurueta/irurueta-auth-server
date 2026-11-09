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
package com.irurueta.authserver.authorization.domain.totp;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

// tag::totp-uri[]
/**
 * Builds the {@code otpauth://} URI that authenticator applications read from a QR code to enrol a secret.
 */
public final class TotpUri {

    /**
     * Not instantiable: a holder of static helpers.
     */
    private TotpUri() {
    }

    /**
     * Builds the URI of a TOTP enrolment.
     *
     * @param issuer  name of the service, shown by the authenticator.
     * @param account name of the account, shown by the authenticator.
     * @param secret  the shared secret.
     * @return the URI, with the parameters of {@link TotpAlgorithm}.
     * @throws IllegalArgumentException if the issuer or the account is blank.
     */
    public static String build(final String issuer, final String account, final byte[] secret) {
        requireText(issuer, "issuer");
        requireText(account, "account");
        final var encodedIssuer = encode(issuer);
        return "otpauth://totp/" + encodedIssuer + ':' + encode(account)
                + "?secret=" + Base32.encode(secret)
                + "&issuer=" + encodedIssuer
                + "&period=" + TotpAlgorithm.PERIOD_SECONDS
                + "&digits=" + TotpAlgorithm.DIGITS
                + "&algorithm=" + TotpAlgorithm.ALGORITHM_NAME;
    }

    /**
     * Percent-encodes a value, with spaces as {@code %20} as a URI path requires.
     *
     * @param value the value to encode.
     * @return the encoded value.
     */
    private static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
// end::totp-uri[]

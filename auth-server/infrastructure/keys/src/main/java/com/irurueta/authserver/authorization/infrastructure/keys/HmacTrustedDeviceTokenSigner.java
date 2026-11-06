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

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceTokenSigner;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

// tag::mfa-trusted-device-signature[]
/**
 * {@link TrustedDeviceTokenSigner} that signs the trusted-device cookie with HMAC-SHA256, under a key derived from the
 * key-encryption secret for this purpose only ({@link PurposeKeyDerivation}). The value is
 * {@code token.signature}, the signature Base64url encoded without padding; it is compared in constant time.
 */
@Component
public class HmacTrustedDeviceTokenSigner implements TrustedDeviceTokenSigner {

    /** Label of the purpose the key is derived for. */
    public static final String PURPOSE = "trusted-device-cookie";

    /** Separator between the token and its signature. */
    private static final char SEPARATOR = '.';

    /** Name of the MAC algorithm. */
    private static final String ALGORITHM = "HmacSHA256";

    /** The signing key. */
    private final SecretKeySpec key;

    /**
     * Derives the signing key.
     *
     * @param derivation derives the key of a purpose from the key-encryption secret.
     */
    public HmacTrustedDeviceTokenSigner(final PurposeKeyDerivation derivation) {
        key = new SecretKeySpec(derivation.keyFor(PURPOSE), ALGORITHM);
    }

    @Override
    public String sign(final String token) {
        return token + SEPARATOR + Base64.getUrlEncoder().withoutPadding().encodeToString(mac(token));
    }

    @Override
    public Optional<String> verify(final String signedValue) {
        if (!StringUtils.hasText(signedValue)) {
            return Optional.empty();
        }
        final var separator = signedValue.lastIndexOf(SEPARATOR);
        if (separator <= 0 || separator == signedValue.length() - 1) {
            return Optional.empty();
        }
        final var token = signedValue.substring(0, separator);
        final byte[] presented;
        try {
            presented = Base64.getUrlDecoder().decode(signedValue.substring(separator + 1));
        } catch (final IllegalArgumentException e) {
            return Optional.empty();
        }
        return MessageDigest.isEqual(mac(token), presented) ? Optional.of(token) : Optional.empty();
    }

    /**
     * Computes the signature of a token.
     *
     * @param token the token.
     * @return the HMAC-SHA256 of its UTF-8 bytes.
     */
    private byte[] mac(final String token) {
        try {
            final var mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
// end::mfa-trusted-device-signature[]

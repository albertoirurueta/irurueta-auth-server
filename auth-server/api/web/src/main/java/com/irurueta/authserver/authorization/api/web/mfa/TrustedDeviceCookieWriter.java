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

package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.application.mfa.CreatedTrustedDevice;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Writes the cookie that identifies a trusted device. The {@code __Host-} prefix makes the browser accept it only
 * over HTTPS, with {@code Path=/} and no {@code Domain}; it is {@code HttpOnly} so scripts cannot read it and
 * {@code SameSite=Lax} so it is not sent on cross-site subrequests. It lives as long as the device stays trusted.
 */
@Component
@RequiredArgsConstructor
public class TrustedDeviceCookieWriter {

    /** Name of the cookie. */
    public static final String COOKIE_NAME = "__Host-TRUSTED-DEVICE";

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Adds the cookie of a device that has just been trusted to a response.
     *
     * @param response the response.
     * @param created  the trusted device and its raw token.
     */
    public void write(final HttpServletResponse response, final CreatedTrustedDevice created) {
        final var lifetime = Duration.between(clock.instant(), created.device().expiresAt());
        final var cookie = ResponseCookie.from(COOKIE_NAME, created.token())
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(lifetime.isNegative() ? Duration.ZERO : lifetime)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}

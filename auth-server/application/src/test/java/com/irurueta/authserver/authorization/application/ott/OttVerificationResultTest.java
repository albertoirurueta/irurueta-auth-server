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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OttVerificationResult}.
 */
class OttVerificationResultTest {

    /**
     * Verifies the result of an accepted code.
     */
    @Test
    void success_whenChannelIsGiven_carriesTheChannel() {
        final var result = OttVerificationResult.success(OttChannel.SMS);

        assertTrue(result.isSuccess());
        assertEquals(OttVerificationResult.Status.SUCCESS, result.status());
        assertEquals(OttChannel.SMS, result.channel());
    }

    /**
     * Verifies the result of a rejected code.
     */
    @Test
    void failure_whenCalled_isNotSuccessAndHasNoChannel() {
        final var result = OttVerificationResult.failure();

        assertFalse(result.isSuccess());
        assertEquals(OttVerificationResult.Status.FAILURE, result.status());
        assertNull(result.channel());
        assertSame(result, OttVerificationResult.failure());
    }

    /**
     * Verifies the result of a locked second factor.
     */
    @Test
    void locked_whenCalled_isNotSuccessAndHasNoChannel() {
        final var result = OttVerificationResult.locked();

        assertFalse(result.isSuccess());
        assertEquals(OttVerificationResult.Status.LOCKED, result.status());
        assertNull(result.channel());
    }
}

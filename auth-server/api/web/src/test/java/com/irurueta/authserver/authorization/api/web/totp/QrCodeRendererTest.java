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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link QrCodeRenderer}.
 */
class QrCodeRendererTest {

    /** Text encoded by the tests. */
    private static final String CONTENT = "otpauth://totp/Issuer:alice?secret=ABC&issuer=Issuer";

    /** Renderer under test. */
    private final QrCodeRenderer renderer = new QrCodeRenderer();

    /**
     * Verifies that the result is a PNG data URI that decodes back to the text.
     *
     * @throws Exception if the image cannot be decoded.
     */
    @Test
    void render_whenContentIsGiven_returnsPngDataUriThatDecodesToTheContent() throws Exception {
        final var uri = renderer.render(CONTENT);

        assertTrue(uri.startsWith(QrCodeRenderer.DATA_URI_PREFIX));
        final var png = Base64.getDecoder().decode(uri.substring(QrCodeRenderer.DATA_URI_PREFIX.length()));
        final var image = ImageIO.read(new ByteArrayInputStream(png));
        assertNotNull(image);
        assertEquals(QrCodeRenderer.SIZE, image.getWidth());
        final var decoded = new MultiFormatReader().decode(
                new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image))));
        assertEquals(CONTENT, decoded.getText());
    }
}

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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Renders a text as a QR code, as a PNG image in a {@code data:} URI an authenticator app enrolment page can show
 * without another request. The image is built in memory and never stored or logged, since it carries a secret.
 */
@Component
public class QrCodeRenderer {

    /** Prefix of the {@code data:} URI of a PNG image. */
    public static final String DATA_URI_PREFIX = "data:image/png;base64,";

    /** Width and height of the image, in pixels. */
    static final int SIZE = 256;

    /** Name of the image format. */
    private static final String PNG = "PNG";

    /** Quiet zone around the code, in modules. */
    private static final int MARGIN = 2;

    /**
     * Renders a text.
     *
     * @param content the text to encode.
     * @return a {@code data:image/png;base64,...} URI of the QR code.
     * @throws IllegalStateException if the text cannot be encoded.
     */
    public String render(final String content) {
        try {
            final var matrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, SIZE, SIZE,
                    Map.of(EncodeHintType.MARGIN, MARGIN));
            final var image = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, PNG, image);
            return DATA_URI_PREFIX + Base64.getEncoder().encodeToString(image.toByteArray());
        } catch (final WriterException | IOException e) {
            throw new IllegalStateException("The QR code could not be rendered", e);
        }
    }
}

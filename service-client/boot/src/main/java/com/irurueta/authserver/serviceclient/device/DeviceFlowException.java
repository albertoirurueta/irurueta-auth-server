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

package com.irurueta.authserver.serviceclient.device;

/**
 * The device flow could not finish: the request failed, the user denied it, the device code expired or the program was
 * interrupted.
 */
public class DeviceFlowException extends RuntimeException {

    /** The serial version u i d. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what went wrong; never contains a token.
     */
    public DeviceFlowException(final String message) {
        super(message);
    }

    /**
     * Creates the exception.
     *
     * @param message what went wrong; never contains a token.
     * @param cause   the underlying failure.
     */
    public DeviceFlowException(final String message, final Throwable cause) {
        super(message, cause);
    }
}

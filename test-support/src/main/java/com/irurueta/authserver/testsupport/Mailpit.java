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
package com.irurueta.authserver.testsupport;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Describes the Mailpit container the one-time token tests read the e-mail of: the pinned image, its two ports and a
 * factory that builds the container and the client of its HTTP API. Mailpit accepts any message over SMTP and exposes
 * what it received over HTTP, so a test reads the code or the link the application mailed.
 */
public final class Mailpit {

    /** Docker image of Mailpit, pinned to a version so a run never depends on a moving tag. */
    public static final String IMAGE = "axllent/mailpit:v1.29.0";

    /** Port the SMTP server listens on inside the container. */
    public static final int SMTP_PORT = 1025;

    /** Port the HTTP API listens on inside the container. */
    public static final int API_PORT = 8025;

    /** Path that answers once the HTTP API is ready. */
    private static final String READY_PATH = "/api/v1/info";

    /** Prevents instantiation of this utility class. */
    private Mailpit() {
    }

    /**
     * Creates a Mailpit container, not yet started.
     *
     * @return the container, which waits for the HTTP API to answer before it counts as started.
     */
    public static GenericContainer<?> newContainer() {
        return new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withExposedPorts(SMTP_PORT, API_PORT)
                .waitingFor(Wait.forHttp(READY_PATH).forPort(API_PORT));
    }

    /**
     * Builds the client of the HTTP API of a started container.
     *
     * @param container a started Mailpit container.
     * @return the client.
     */
    public static MailpitClient clientOf(final GenericContainer<?> container) {
        return new MailpitClient("http://" + container.getHost() + ":" + container.getMappedPort(API_PORT));
    }
}

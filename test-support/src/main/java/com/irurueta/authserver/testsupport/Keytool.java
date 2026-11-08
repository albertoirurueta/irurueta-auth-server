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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs the {@code keytool} of the JDK that runs the tests and cleans up the temporary directories its key stores live
 * in; the JDK has no public API to issue a certificate. Shared by the generators of test certificates, so none of them
 * keeps a key, a certificate or a key store beyond the time a test needs it.
 */
final class Keytool {

    /** Longest time {@code keytool} may take. */
    private static final long TIMEOUT_SECONDS = 60;

    /** Not instantiable. */
    private Keytool() {
    }

    /**
     * Runs {@code keytool} and waits for it.
     *
     * @param arguments the arguments, without the executable.
     * @throws IOException if it cannot run or fails.
     */
    static void run(final List<String> arguments) throws IOException {
        final var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(arguments);
        final var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        try {
            final var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                throw new IOException("keytool failed: " + output);
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("Interrupted while running keytool", e);
        }
    }

    /**
     * Deletes a directory and what it holds, ignoring a failure.
     *
     * @param directory the directory, may be {@code null}.
     */
    static void delete(final Path directory) {
        if (directory == null) {
            return;
        }
        try {
            Files.walkFileTree(directory, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(final Path file, final BasicFileAttributes attributes)
                        throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(final Path dir, final IOException error)
                        throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (final IOException e) {
            // a temporary directory that cannot be removed is left to the operating system
            directory.toFile().deleteOnExit();
        }
    }
}

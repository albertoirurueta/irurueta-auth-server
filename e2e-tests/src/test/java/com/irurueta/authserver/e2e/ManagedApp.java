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

package com.irurueta.authserver.e2e;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * A Spring Boot application launched from its packaged jar in a child JVM, with its console output captured so a
 * test can wait for a log line.
 */
final class ManagedApp {

    /**
     * Number of trailing output lines included in the failure message when a log line never shows up.
     */
    private static final int OUTPUT_TAIL_LINES = 40;

    /**
     * Longest single wait for new output, in milliseconds, so a dead process is noticed promptly.
     */
    private static final long POLL_MILLIS = 500;

    /**
     * Time granted to the process to exit gracefully before it is killed.
     */
    private static final Duration STOP_TIMEOUT = Duration.ofSeconds(15);

    /**
     * The child JVM.
     */
    private final Process process;

    /**
     * Console lines captured so far; also the monitor guarding itself.
     */
    private final List<String> output = new ArrayList<>();

    /**
     * Wraps a started process.
     *
     * @param process the child JVM.
     */
    private ManagedApp(final Process process) {
        this.process = process;
    }

    /**
     * Launches {@code java -jar <jar> <args>} with extra environment variables.
     *
     * @param jar         the packaged application.
     * @param args        program arguments.
     * @param environment {@code NAME=value} entries added to the child's environment.
     * @return the running application.
     * @throws IOException if the process cannot be started.
     */
    static ManagedApp start(final Path jar, final List<String> args, final List<String> environment)
            throws IOException {
        final var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-jar");
        command.add(jar.toString());
        command.addAll(args);
        final var builder = new ProcessBuilder(command).redirectErrorStream(true);
        for (final var entry : environment) {
            final var idx = entry.indexOf('=');
            builder.environment().put(entry.substring(0, idx), entry.substring(idx + 1));
        }
        final var app = new ManagedApp(builder.start());
        final var reader = new Thread(app::pump, "e2e-output-" + jar.getFileName());
        reader.setDaemon(true);
        reader.start();
        return app;
    }

    /**
     * Waits until a console line matches.
     *
     * @param pattern the pattern to look for.
     * @param timeout how long to wait.
     * @return the pattern's first group, or the whole match when it has no group.
     * @throws InterruptedException  if the wait is interrupted.
     * @throws IllegalStateException if the line did not show up in time or the process ended first.
     */
    String await(final Pattern pattern, final Duration timeout) throws InterruptedException {
        final var deadline = System.nanoTime() + timeout.toNanos();
        var seen = 0;
        synchronized (output) {
            while (true) {
                while (seen < output.size()) {
                    final var matcher = pattern.matcher(output.get(seen++));
                    if (matcher.find()) {
                        return matcher.groupCount() > 0 ? matcher.group(1) : matcher.group();
                    }
                }
                final var remaining = deadline - System.nanoTime();
                if (remaining <= 0 || !process.isAlive() && seen >= output.size()) {
                    throw new IllegalStateException("Application did not log " + pattern + ". Output tail:\n"
                            + String.join("\n", tail()));
                }
                output.wait(Math.min(TimeUnit.NANOSECONDS.toMillis(remaining), POLL_MILLIS));
            }
        }
    }

    /**
     * Waits for the application to end by itself.
     *
     * @param timeout longest time to wait.
     * @return the exit code of the process.
     * @throws InterruptedException if the thread is interrupted while waiting.
     */
    int awaitExit(final Duration timeout) throws InterruptedException {
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            synchronized (output) {
                throw new IllegalStateException("Application did not end. Output tail:\n"
                        + String.join("\n", tail()));
            }
        }
        return process.exitValue();
    }

    /**
     * Stops the process, forcibly when it does not exit in time.
     */
    void stop() {
        process.destroy();
        try {
            if (!process.waitFor(STOP_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }

    /**
     * Copies the console output into {@link #output} until the process closes it.
     */
    private void pump() {
        try (var lines = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = lines.readLine()) != null) {
                synchronized (output) {
                    output.add(line);
                    output.notifyAll();
                }
            }
        } catch (final IOException ignored) {
            // process ended
        }
    }

    /**
     * Returns the last captured lines; the caller must hold the {@link #output} monitor.
     *
     * @return the trailing lines of the output.
     */
    private List<String> tail() {
        return output.subList(Math.max(0, output.size() - OUTPUT_TAIL_LINES), output.size());
    }
}

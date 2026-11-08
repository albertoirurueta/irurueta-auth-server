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

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One run of the packaged {@code service-client} jar: it starts with a profile, program arguments and environment
 * variables, ends by itself and leaves its console output and exit code.
 */
final class ServiceClientRun {

    /** Longest wait for a run to end. */
    private static final Duration RUN_TIMEOUT = Duration.ofSeconds(90);

    /** Matches the access token line the tool prints when asked to. */
    private static final Pattern ACCESS_TOKEN = Pattern.compile("^Access token: (\\S+)");

    /** Delay that lets the reader thread drain the pipe after the process ended, in milliseconds. */
    private static final long DRAIN_MILLIS = 200;

    /** Exit code of the process, zero when it ended without error. */
    private final int exitCode;

    /** Console lines (documents as JSON lines, the printed access token, the log). */
    private final List<String> output;

    /**
     * Keeps what a run left.
     *
     * @param exitCode exit code of the process.
     * @param output   console lines.
     */
    private ServiceClientRun(final int exitCode, final List<String> output) {
        this.exitCode = exitCode;
        this.output = List.copyOf(output);
    }

    /**
     * Returns the exit code.
     *
     * @return the exit code of the process, zero when it ended without error.
     */
    int exitCode() {
        return exitCode;
    }

    /**
     * Runs the jar to the end.
     *
     * @param profile     the Spring profile that selects the runner ({@code client-credentials} or
     *                    {@code token-exchange}).
     * @param arguments   program arguments added after the profile.
     * @param environment {@code NAME=value} entries added to the environment of the process.
     * @return what the run left.
     * @throws Exception if the process cannot be started or does not end in time.
     */
    static ServiceClientRun run(final String profile, final List<String> arguments, final List<String> environment)
            throws Exception {
        final var allArguments = new ArrayList<String>();
        allArguments.add("--spring.profiles.active=" + profile);
        allArguments.addAll(arguments);
        final var app = ManagedApp.start(RunningAuthServer.jar("serviceclient.jar"), allArguments, environment);
        try {
            final var exitCode = app.awaitExit(RUN_TIMEOUT);
            // the reader thread may still be draining the pipe a moment after the process ended
            Thread.sleep(DRAIN_MILLIS);
            return new ServiceClientRun(exitCode, app.output());
        } finally {
            app.stop();
        }
    }

    /**
     * Returns the access token the run printed.
     *
     * @return the access token.
     * @throws IllegalStateException if the run printed none.
     */
    String accessToken() {
        return output.stream().map(ACCESS_TOKEN::matcher).filter(Matcher::find)
                .map(matcher -> matcher.group(1)).findFirst()
                .orElseThrow(() -> new IllegalStateException("The run printed no access token: " + output));
    }

    /**
     * Returns the documents the run printed, one JSON object per line.
     *
     * @return the JSON lines.
     */
    List<String> documents() {
        return output.stream().filter(line -> line.startsWith("{")).toList();
    }

    /**
     * Describes the run for an assertion message, without the access token.
     *
     * @return the exit code and the output lines that are not the access token.
     */
    String describe() {
        return "exit code " + exitCode + ", output:\n"
                + String.join("\n", output.stream().filter(line -> !ACCESS_TOKEN.matcher(line).find()).toList());
    }

    /**
     * Returns a path as the {@code file:} URL Spring expects for a resource location.
     *
     * @param path the file.
     * @return its {@code file:} URL.
     */
    static String fileUrl(final Path path) {
        return "file:" + path.toAbsolutePath();
    }
}

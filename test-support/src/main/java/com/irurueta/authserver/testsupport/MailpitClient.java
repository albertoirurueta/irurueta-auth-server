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
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reads the messages a Mailpit server received through its HTTP API, so a test finds the code or the link the
 * application mailed to a recipient. Every call is a plain HTTP request; there is no state besides the server's.
 */
public final class MailpitClient {

    /** Longest wait for one HTTP call. */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(10);

    /** Default longest wait for a message to arrive. */
    private static final Duration DEFAULT_WAIT = Duration.ofSeconds(15);

    /** Pause between two polls of the server. */
    private static final long POLL_MILLIS = 100L;

    /** HTTP status of a successful call. */
    private static final int HTTP_OK = 200;

    /** Matches the magic link a message carries and captures its token. */
    private static final Pattern LINK_TOKEN = Pattern.compile("/login/ott/confirm\\?token=([0-9A-Za-z-]+)");

    /** Matches the whole magic link a message carries. */
    private static final Pattern FULL_LINK = Pattern.compile("(https?://\\S*/login/ott/confirm\\?token=[0-9A-Za-z-]+)");

    /** Matches the numeric code of a message: a run of digits that stands alone. */
    private static final Pattern CODE = Pattern.compile("(?<![0-9A-Za-z])([0-9]{4,10})(?![0-9A-Za-z])");

    /** Reads the JSON answers. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** Sends the HTTP calls. */
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(CALL_TIMEOUT).build();

    /** Base URL of the HTTP API, without a trailing slash. */
    private final String baseUrl;

    /**
     * Creates the client.
     *
     * @param baseUrl base URL of the HTTP API, such as {@code http://localhost:8025}.
     */
    public MailpitClient(final String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * A message Mailpit received.
     *
     * @param id      identifier Mailpit gave it.
     * @param subject subject of the message.
     * @param text    plain-text body.
     * @param html    HTML body, empty when the message has none.
     */
    public record Message(String id, String subject, String text, String html) {

        /**
         * Reads the token of the magic link the message carries.
         *
         * @return the token of the link.
         * @throws IllegalStateException if the message carries no link.
         */
        public String linkToken() {
            final var matcher = LINK_TOKEN.matcher(text);
            if (!matcher.find()) {
                throw new IllegalStateException("The message carries no magic link: " + subject);
            }
            return matcher.group(1);
        }

        /**
         * Reads the full magic link of the message, as the user would open it.
         *
         * @return the URL of the link.
         * @throws IllegalStateException if the message carries no link.
         */
        public String link() {
            final var matcher = FULL_LINK.matcher(text);
            if (!matcher.find()) {
                throw new IllegalStateException("The message carries no magic link: " + subject);
            }
            return matcher.group(1);
        }

        /**
         * Reads the numeric code of the message.
         *
         * @return the digits of the code.
         * @throws IllegalStateException if the message carries no code.
         */
        public String code() {
            final Matcher matcher = CODE.matcher(text);
            if (!matcher.find()) {
                throw new IllegalStateException("The message carries no code: " + subject);
            }
            return matcher.group(1);
        }
    }

    /**
     * Waits for the first message addressed to a recipient.
     *
     * @param recipient address the message was sent to.
     * @return the message.
     * @throws IllegalStateException if none arrives in time.
     */
    public Message awaitMessageTo(final String recipient) {
        return awaitMessagesTo(recipient, 1).getFirst();
    }

    /**
     * Waits until at least a number of messages addressed to a recipient arrived.
     *
     * @param recipient address the messages were sent to.
     * @param count     number of messages to wait for.
     * @return the messages, oldest first.
     * @throws IllegalStateException if they do not arrive in time.
     */
    public List<Message> awaitMessagesTo(final String recipient, final int count) {
        final var deadline = System.nanoTime() + DEFAULT_WAIT.toNanos();
        while (true) {
            final var messages = messagesTo(recipient);
            if (messages.size() >= count) {
                return messages;
            }
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("Expected " + count + " message(s) for the recipient but found "
                        + messages.size());
            }
            pause();
        }
    }

    /**
     * Lists the messages addressed to a recipient that Mailpit holds now.
     *
     * @param recipient address the messages were sent to.
     * @return the messages, oldest first; empty when there are none.
     */
    public List<Message> messagesTo(final String recipient) {
        final var query = URLEncoder.encode("to:\"" + recipient + "\"", StandardCharsets.UTF_8);
        final var summaries = get("/api/v1/search?query=" + query).path("messages");
        final var messages = new ArrayList<Message>();
        for (final var summary : summaries) {
            messages.add(read(summary.path("ID").asString()));
        }
        return List.copyOf(messages.reversed());
    }

    /**
     * Counts the messages addressed to a recipient that Mailpit holds now.
     *
     * @param recipient address the messages were sent to.
     * @return the number of messages.
     */
    public int countMessagesTo(final String recipient) {
        return messagesTo(recipient).size();
    }

    /**
     * Reads one message.
     *
     * @param id identifier Mailpit gave the message.
     * @return the message.
     */
    private Message read(final String id) {
        final var message = get("/api/v1/message/" + id);
        return new Message(id, message.path("Subject").asString(""), message.path("Text").asString(""),
                message.path("HTML").asString(""));
    }

    /**
     * Calls the API with GET and parses the JSON answer.
     *
     * @param path path and query of the call.
     * @return the answer.
     */
    private JsonNode get(final String path) {
        final var request = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(CALL_TIMEOUT).GET().build();
        try {
            final var response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != HTTP_OK) {
                throw new IllegalStateException("Mailpit answered " + response.statusCode() + " to " + path);
            }
            return JSON.readTree(response.body());
        } catch (final IOException e) {
            throw new IllegalStateException("Mailpit could not be reached", e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while calling Mailpit", e);
        }
    }

    /** Sleeps a short while between two polls. */
    private static void pause() {
        try {
            Thread.sleep(POLL_MILLIS);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for a message", e);
        }
    }
}

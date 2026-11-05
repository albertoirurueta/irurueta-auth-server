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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Compares an OpenAPI contract under {@code apis/} with the OpenAPI document a running application serves. Both are
 * reduced to a sorted summary of what a client depends on: the info title and version, the security schemes, for
 * every operation under a path prefix its operation id, tags, security requirements, parameters, request body and
 * status codes, the schema of every media type an answer declares, and the properties and required properties of
 * every schema. Descriptions are left out: they are the contract's prose, rendered by springdoc from the annotations
 * generated from it. Two documents describe the same API when their summaries are equal, and {@code assertEquals} on
 * the two summaries lists exactly what drifted.
 * <p>
 * springdoc documents a few things the contract does not say: it repeats the return type of an operation under
 * every media type the operation produces and on answers declared without a body (such as a {@code 401}), and it
 * adds schemas of its own. {@link #restrictTo(SortedMap, SortedMap)} leaves those out of the served summary; an
 * operation, a status code, a media type or a schema the contract declares and the application does not serve, or
 * serves differently, is still reported.
 * <p>
 * Documents are read with SnakeYAML's safe constructor, which reads YAML and JSON alike, and {@code $ref}s to
 * {@code #/components/...} are resolved, so a contract may share parameters and responses that the served document
 * repeats inline.
 */
public final class OpenApiContract {

    /** HTTP methods an OpenAPI path item may declare an operation for. */
    private static final List<String> METHODS = List.of("get", "put", "post", "delete", "options", "head", "patch",
            "trace");

    /** Prefix of a local reference. */
    private static final String LOCAL_REF = "#/";

    /** Key of a reference. */
    private static final String REF = "$ref";

    /** Key of the security requirements. */
    private static final String SECURITY = "security";

    /** Key of the content of a request body or a response. */
    private static final String CONTENT = "content";

    /** Key of a schema. */
    private static final String SCHEMA = "schema";

    /** Key of the components. */
    private static final String COMPONENTS = "components";

    /** Prefix of the summary keys of the schemas. */
    private static final String SCHEMA_KEY = "schema ";

    /** Infix of the summary keys of the media types of an answer. */
    private static final String CONTENT_KEY = " content ";

    /** Value of the summary key of a status code: its body is described by the media type keys. */
    private static final String RESPONSE = "declared";

    /** Utility class: not meant to be instantiated. */
    private OpenApiContract() {
    }

    /**
     * Reads an OpenAPI document from a file.
     *
     * @param file YAML or JSON file.
     * @return the document.
     * @throws IOException if the file cannot be read.
     */
    public static Map<String, Object> read(final Path file) throws IOException {
        return parse(Files.readString(file, StandardCharsets.UTF_8));
    }

    /**
     * Parses an OpenAPI document.
     *
     * @param text YAML or JSON text.
     * @return the document.
     */
    public static Map<String, Object> parse(final String text) {
        return new Yaml(new SafeConstructor(new LoaderOptions())).load(text);
    }

    /**
     * Summarizes the API a document describes.
     *
     * @param document   the OpenAPI document.
     * @param pathPrefix prefix of the paths that belong to the API, such as {@code /api/}.
     * @return the summary, sorted by key.
     */
    public static SortedMap<String, String> summarize(final Map<String, Object> document, final String pathPrefix) {
        final var summary = new TreeMap<String, String>();
        final var info = map(document.get("info"));
        summary.put("info", info.get("title") + " " + info.get("version"));
        final var components = map(document.get(COMPONENTS));
        map(components.get("securitySchemes")).forEach((name, scheme) ->
                summary.put("securityScheme " + name, describeScheme(map(scheme))));
        map(components.get("schemas")).forEach((name, schema) ->
                summary.put(SCHEMA_KEY + name, describeSchemaProperties(map(schema))));
        final var globalSecurity = document.get(SECURITY);
        map(document.get("paths")).forEach((path, item) -> {
            if (path.startsWith(pathPrefix)) {
                summarizePath(document, path, map(item), globalSecurity, summary);
            }
        });
        return summary;
    }

    /**
     * Restricts the summary of a served document to the schemas and the media types of the answers the contract
     * declares, leaving out what the server documents by itself.
     *
     * @param served   the summary of the served document.
     * @param contract the summary of the contract.
     * @return the restricted summary.
     */
    public static SortedMap<String, String> restrictTo(final SortedMap<String, String> served,
                                                       final SortedMap<String, String> contract) {
        final var restricted = new TreeMap<String, String>();
        served.forEach((key, value) -> {
            final var optional = key.startsWith(SCHEMA_KEY) || key.contains(CONTENT_KEY);
            if (!optional || contract.containsKey(key)) {
                restricted.put(key, value);
            }
        });
        return restricted;
    }

    /**
     * Summarizes every operation of a path.
     *
     * @param document       the document, to resolve references.
     * @param path           the path.
     * @param item           the path item.
     * @param globalSecurity the security requirements of the document, used by operations that declare none.
     * @param summary        the summary to fill.
     */
    private static void summarizePath(final Map<String, Object> document, final String path,
                                      final Map<String, Object> item, final Object globalSecurity,
                                      final Map<String, String> summary) {
        final var pathParameters = list(item.get("parameters"));
        for (final var method : METHODS) {
            final var operation = map(item.get(method));
            if (operation.isEmpty()) {
                continue;
            }
            final var key = method.toUpperCase(Locale.ROOT) + " " + path;
            final var parameters = new ArrayList<Object>(pathParameters);
            parameters.addAll(list(operation.get("parameters")));
            final var security = operation.containsKey(SECURITY) ? operation.get(SECURITY) : globalSecurity;
            summary.put(key, "operationId=" + operation.get("operationId")
                    + "; tags=" + sorted(list(operation.get("tags")))
                    + "; security=" + describeSecurity(list(security))
                    + "; parameters=" + describeParameters(document, parameters)
                    + "; requestBody=" + describeBody(map(resolve(document, operation.get("requestBody")))));
            map(operation.get("responses")).forEach((code, response) -> {
                summary.put(key + " " + code, RESPONSE);
                map(map(resolve(document, response)).get(CONTENT)).forEach((mediaType, media) ->
                        summary.put(key + " " + code + CONTENT_KEY + mediaType,
                                describeSchema(map(map(media).get(SCHEMA)))));
            });
        }
    }

    /**
     * Describes a security scheme by the fields a client relies on.
     *
     * @param scheme the scheme.
     * @return its description.
     */
    private static String describeScheme(final Map<String, Object> scheme) {
        return List.of("type", "scheme", "bearerFormat", "in", "name").stream()
                .filter(scheme::containsKey)
                .map(field -> field + "=" + scheme.get(field))
                .collect(Collectors.joining(", "));
    }

    /**
     * Describes the properties of a schema.
     *
     * @param schema the schema.
     * @return its sorted property names and required property names.
     */
    private static String describeSchemaProperties(final Map<String, Object> schema) {
        return "properties=" + sorted(map(schema.get("properties")).keySet())
                + "; required=" + sorted(list(schema.get("required")));
    }

    /**
     * Describes security requirements, an absent or empty list meaning a public operation.
     *
     * @param requirements the requirements.
     * @return their sorted description, such as {@code [bearer[admin]]}.
     */
    private static String describeSecurity(final List<Object> requirements) {
        final var described = new ArrayList<String>();
        for (final var requirement : requirements) {
            map(requirement).forEach((name, roles) -> described.add(name + sorted(list(roles))));
        }
        return sorted(described).toString();
    }

    /**
     * Describes parameters by location, name and whether they are required.
     *
     * @param document   the document, to resolve references.
     * @param parameters the parameters.
     * @return their sorted description.
     */
    private static String describeParameters(final Map<String, Object> document, final List<Object> parameters) {
        return sorted(parameters.stream()
                .map(parameter -> map(resolve(document, parameter)))
                .map(parameter -> parameter.get("in") + ":" + parameter.get("name") + ":"
                        + Boolean.TRUE.equals(parameter.get("required")))
                .toList()).toString();
    }

    /**
     * Describes a request body.
     *
     * @param body the body, already resolved, empty when the operation takes none.
     * @return its description.
     */
    private static String describeBody(final Map<String, Object> body) {
        if (body.isEmpty()) {
            return "none";
        }
        return "required=" + Boolean.TRUE.equals(body.get("required")) + " "
                + describeContent(map(body.get(CONTENT)));
    }

    /**
     * Describes a content map by media type and schema.
     *
     * @param content the content map, empty when there is no body.
     * @return its sorted description.
     */
    private static String describeContent(final Map<String, Object> content) {
        final var described = new ArrayList<String>();
        content.forEach((mediaType, media) ->
                described.add(mediaType + ":" + describeSchema(map(map(media).get(SCHEMA)))));
        return sorted(described).toString();
    }

    /**
     * Describes a schema by name, or by type for an inline one.
     *
     * @param schema the schema, empty when there is none.
     * @return its description, such as {@code ClientResponse} or {@code array<ClientResponse>}.
     */
    private static String describeSchema(final Map<String, Object> schema) {
        if (schema.isEmpty()) {
            return "none";
        }
        if (schema.containsKey(REF)) {
            final var ref = schema.get(REF).toString();
            return ref.substring(ref.lastIndexOf('/') + 1);
        }
        if ("array".equals(schema.get("type"))) {
            return "array<" + describeSchema(map(schema.get("items"))) + ">";
        }
        return String.valueOf(schema.get("type"));
    }

    /**
     * Resolves a local reference, such as {@code #/components/responses/Unauthorized}.
     *
     * @param document the document.
     * @param node     the node, which may be a reference.
     * @return the node it refers to, or the node itself when it is not a reference.
     */
    private static Object resolve(final Map<String, Object> document, final Object node) {
        final var value = map(node);
        if (!value.containsKey(REF)) {
            return node;
        }
        final var ref = value.get(REF).toString();
        if (!ref.startsWith(LOCAL_REF)) {
            throw new IllegalArgumentException("Only local references are supported: " + ref);
        }
        Object target = document;
        for (final var segment : ref.substring(LOCAL_REF.length()).split("/")) {
            target = map(target).get(segment);
        }
        return Objects.requireNonNull(target, () -> "Unresolved reference " + ref);
    }

    /**
     * Sorts values by their text.
     *
     * @param values the values.
     * @return a sorted list of their texts.
     */
    private static List<String> sorted(final Collection<?> values) {
        return values.stream().map(String::valueOf).sorted().toList();
    }

    /**
     * Reads a node as a map.
     *
     * @param node the node.
     * @return the node, or an empty map when it is absent or not a map.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(final Object node) {
        return node instanceof Map<?, ?> value ? (Map<String, Object>) value : Map.of();
    }

    /**
     * Reads a node as a list.
     *
     * @param node the node.
     * @return the node, or an empty list when it is absent or not a list.
     */
    @SuppressWarnings("unchecked")
    private static List<Object> list(final Object node) {
        return node instanceof List<?> value ? (List<Object>) value : List.of();
    }
}

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
package com.irurueta.authserver.bff.api.web.documents;

import com.irurueta.authserver.bff.api.web.login.StepUpLoginParameters;
import com.irurueta.authserver.bff.domain.documents.DocumentsStepUpRequiredException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Maps a step-up request of the resource server onto the extra members of the {@code step-up-required} problem, the
 * values the SPA passes back to {@code GET /bff/login}. They are values the resource server chose, so they are kept
 * within what that endpoint accepts, otherwise the login would answer {@code 400} and the user could never step up:
 * <ul>
 *   <li>{@code acrValues}: only the references of the accepted format are kept, and none at all when the result would
 *       be empty or longer than the login allows;</li>
 *   <li>{@code maxAge}: capped at the login's maximum, which is stricter than what the resource server asked for, so
 *       the new sign-in still satisfies it.</li>
 * </ul>
 */
@Component
public class StepUpProblemMapper {

    /** Problem member carrying the authentication context classes. */
    static final String ACR_VALUES_PROPERTY = "acrValues";

    /** Problem member carrying the maximum age, in seconds. */
    static final String MAX_AGE_PROPERTY = "maxAge";

    /** Separator of the authentication context class references: any run of whitespace. */
    private static final String ACR_VALUES_SEPARATOR = "\\s+";

    /**
     * Builds the extra problem members of a step-up request.
     *
     * @param exception the step-up request, with the values the resource server asked for.
     * @return the members, in a stable order; empty when the resource server named no usable value.
     */
    public Map<String, Object> toProblemProperties(final DocumentsStepUpRequiredException exception) {
        final var properties = new LinkedHashMap<String, Object>();
        exception.getAcrValues()
                .map(StepUpProblemMapper::acceptedAcrValues)
                .filter(acrValues -> !acrValues.isEmpty()
                        && acrValues.length() <= StepUpLoginParameters.MAX_ACR_VALUES_LENGTH)
                .ifPresent(acrValues -> properties.put(ACR_VALUES_PROPERTY, acrValues));
        exception.getMaxAge().ifPresent(maxAge -> properties.put(MAX_AGE_PROPERTY,
                Math.min(maxAge.toSeconds(), StepUpLoginParameters.MAX_AGE_LIMIT_SECONDS)));
        return properties;
    }

    /**
     * Keeps the authentication context class references of the format the login accepts.
     *
     * @param acrValues space-separated references.
     * @return the accepted ones, separated by one space; empty when none is.
     */
    private static String acceptedAcrValues(final String acrValues) {
        return Arrays.stream(acrValues.trim().split(ACR_VALUES_SEPARATOR))
                .filter(acr -> StepUpLoginParameters.ACR_VALUE.matcher(acr).matches())
                .collect(Collectors.joining(" "));
    }
}

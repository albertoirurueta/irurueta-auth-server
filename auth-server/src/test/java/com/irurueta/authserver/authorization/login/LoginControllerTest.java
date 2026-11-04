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

package com.irurueta.authserver.authorization.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.ui.ExtendedModelMap;

class LoginControllerTest {

    private static LoginMethodFragment fragment(final String fragmentName, final int order) {
        return new LoginMethodFragment() {
            @Override
            public String templateName() {
                return "test-fragments";
            }

            @Override
            public String fragmentName() {
                return fragmentName;
            }

            @Override
            public int order() {
                return order;
            }
        };
    }

    @Test
    void login_withoutFragments_returnsEmptyList() {
        final var model = new ExtendedModelMap();

        final var view = new LoginController(List.of()).login(model);

        assertThat(view).isEqualTo("login");
        assertThat((List<?>) model.get("fragments")).isEmpty();
    }

    @Test
    void login_withTwoFragments_returnsThemSortedByOrder() {
        final var second = fragment("second", 20);
        final var first = fragment("first", 10);
        final var model = new ExtendedModelMap();

        new LoginController(List.of(second, first)).login(model);

        assertThat(model.get("fragments")).isEqualTo(List.of(first, second));
    }

    @Test
    void reference_joinsTemplateAndFragment() {
        assertThat(fragment("first", 1).reference()).isEqualTo("test-fragments :: first");
    }
}

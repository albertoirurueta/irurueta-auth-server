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
package com.irurueta.authserver.authorization.api.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Enables {@code @Async} methods for every feature of the application (the delivery of one-time tokens after their
 * transaction commits, ...), which then run on Spring Boot's {@code applicationTaskExecutor}. It lives in the root
 * package so that no feature owns a switch the others rely on, as {@link SchedulingConfiguration} does for scheduled
 * tasks.
 */
@Configuration(proxyBeanMethods = false)
@EnableAsync
public class AsyncConfiguration {
}

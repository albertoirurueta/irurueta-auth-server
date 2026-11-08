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

package com.irurueta.authserver.serviceclient;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.Architectures;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Architecture rules of the hexagon, checked at package granularity over the classes of every module. They
 * complement the {@code bannedDependencies} rules that the {@code pom.xml} of each module declares at jar
 * granularity. {@code boot} is the only module that sees every layer, so it is the only place where these rules
 * can be checked against the whole class graph. The service client has a {@code domain} and an {@code application};
 * the driven adapters (the resource server client and its OAuth2 wiring) follow in {@code infrastructure}, and the
 * rules are written against the layer packages, so an adapter added later is covered without editing them. Its use
 * cases demarcate no transaction (they touch no transactional store: the documents live on the resource server). The
 * {@code device} package is the polling CLI of the device grant, a hand-written boot-level class set (the end-to-end
 * test runs the packaged jar): it is declared as its own layer, allowed explicitly, and must not reach the domain,
 * the application or any adapter. Rules over layers that have no class yet allow an empty set.
 */
@AnalyzeClasses(
        packages = "com.irurueta.authserver.serviceclient",
        importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

    /** Root package of the service client. */
    private static final String ROOT = "com.irurueta.authserver.serviceclient";

    /** Package of the domain layer. */
    private static final String DOMAIN = ROOT + ".domain..";

    /** Package of the application layer. */
    private static final String APPLICATION = ROOT + ".application..";

    /** Package of the infrastructure layer. */
    private static final String INFRASTRUCTURE = ROOT + ".infrastructure..";

    /** Package of the api layer. */
    private static final String API = ROOT + ".api..";

    /** Package of the boot-level device grant CLI. */
    private static final String DEVICE = ROOT + ".device..";

    /** Packages openapi-generator generates into from the contracts under {@code apis/}. */
    private static final String GENERATED = "..generated..";

    /** Packages of the interfaces openapi-generator generates from the contracts under {@code apis/}. */
    private static final String GENERATED_API = "..generated.api..";

    /** Domain depends on nothing but the JDK and Lombok. */
    @ArchTest
    static final ArchRule DOMAIN_DEPENDS_ON_NOTHING_BUT_THE_JDK = classes()
            .that().resideInAPackage(DOMAIN)
            .should().onlyDependOnClassesThat().resideInAnyPackage(DOMAIN, "java..", "javax..", "lombok..");

    /** Application depends only on domain and Spring (and the JDK and Lombok). */
    @ArchTest
    static final ArchRule APPLICATION_DEPENDS_ONLY_ON_DOMAIN_AND_SPRING = classes()
            .that().resideInAPackage(APPLICATION)
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                    APPLICATION, DOMAIN, "java..", "javax..", "lombok..", "org.springframework..");

    /** Spring Security types are framework adapters: they never reach the application layer. */
    @ArchTest
    static final ArchRule APPLICATION_NEVER_DEPENDS_ON_SPRING_SECURITY = noClasses()
            .that().resideInAPackage(APPLICATION)
            .should().dependOnClassesThat().resideInAPackage("org.springframework.security..");

    /** The domain and application layers never reach an adapter (driven or driving). */
    @ArchTest
    static final ArchRule INNER_LAYERS_NEVER_DEPEND_ON_ADAPTERS = noClasses()
            .that().resideInAnyPackage(DOMAIN, APPLICATION)
            .should().dependOnClassesThat().resideInAnyPackage(INFRASTRUCTURE, API);

    /** A driving adapter never depends on a driven adapter. */
    @ArchTest
    static final ArchRule API_NEVER_DEPENDS_ON_INFRASTRUCTURE = noClasses()
            .that().resideInAPackage(API)
            .should().dependOnClassesThat().resideInAPackage(INFRASTRUCTURE)
            .allowEmptyShould(true);

    /** A driven adapter never depends on a driving adapter. */
    @ArchTest
    static final ArchRule INFRASTRUCTURE_NEVER_DEPENDS_ON_API = noClasses()
            .that().resideInAPackage(INFRASTRUCTURE)
            .should().dependOnClassesThat().resideInAPackage(API)
            .allowEmptyShould(true);

    /** Driven adapters do not depend on each other. */
    @ArchTest
    static final ArchRule INFRASTRUCTURE_ADAPTERS_DO_NOT_DEPEND_ON_EACH_OTHER = SlicesRuleDefinition.slices()
            .matching(ROOT + ".infrastructure.(*)..")
            .should().notDependOnEachOther()
            .allowEmptyShould(true);

    /** Driving adapters do not depend on each other. */
    @ArchTest
    static final ArchRule API_ADAPTERS_DO_NOT_DEPEND_ON_EACH_OTHER = SlicesRuleDefinition.slices()
            .matching(ROOT + ".api.(*)..")
            .should().notDependOnEachOther()
            .allowEmptyShould(true);

    /** Classes named {@code *UseCase} live in the application layer. */
    @ArchTest
    static final ArchRule USE_CASES_LIVE_IN_APPLICATION = classes()
            .that().haveSimpleNameEndingWith("UseCase")
            .should().resideInAPackage(APPLICATION);

    /** Classes named {@code *Controller} live in the api layer. */
    @ArchTest
    static final ArchRule CONTROLLERS_LIVE_IN_API = classes()
            .that().haveSimpleNameEndingWith("Controller")
            .should().resideInAPackage(API)
            .allowEmptyShould(true);

    /**
     * Contract first (CLAUDE.md, "API contracts"): every HTTP endpoint the application handles is defined in an
     * OpenAPI contract under {@code apis/}, and its mapping lives on the interface openapi-generator produces from it.
     * No hand-written method outside a {@code ..generated..} package carries a mapping annotation.
     */
    @ArchTest
    static final ArchRule NO_HAND_WRITTEN_METHOD_MAPPINGS = noMethods()
            .that().areDeclaredInClassesThat().resideOutsideOfPackage(GENERATED)
            .should().beAnnotatedWith(RequestMapping.class)
            .orShould().beAnnotatedWith(GetMapping.class)
            .orShould().beAnnotatedWith(PostMapping.class)
            .orShould().beAnnotatedWith(PutMapping.class)
            .orShould().beAnnotatedWith(PatchMapping.class)
            .orShould().beAnnotatedWith(DeleteMapping.class);

    /**
     * Contract first (CLAUDE.md, "API contracts"): no hand-written class outside a {@code ..generated..} package
     * carries a mapping annotation either, so a path prefix cannot be added outside the contract.
     */
    @ArchTest
    static final ArchRule NO_HAND_WRITTEN_CLASS_MAPPINGS = noClasses()
            .that().resideOutsideOfPackage(GENERATED)
            .should().beAnnotatedWith(RequestMapping.class)
            .orShould().beAnnotatedWith(GetMapping.class)
            .orShould().beAnnotatedWith(PostMapping.class)
            .orShould().beAnnotatedWith(PutMapping.class)
            .orShould().beAnnotatedWith(PatchMapping.class)
            .orShould().beAnnotatedWith(DeleteMapping.class);

    /**
     * Contract first (CLAUDE.md, "API contracts"): every {@code @Controller} and {@code @RestController} only
     * implements an interface openapi-generator produced from a contract (a {@code ..generated.api..} package), which
     * carries its mappings. Endpoints owned by frameworks (Spring Security's filters, Spring Boot's
     * {@code BasicErrorController}, actuator) are not classes of this application, so they are not checked.
     */
    @ArchTest
    static final ArchRule CONTROLLERS_IMPLEMENT_GENERATED_INTERFACES = classes()
            .that().areMetaAnnotatedWith(Controller.class)
            .should(implementAGeneratedApiInterface())
            .allowEmptyShould(true);

    /** The device CLI is boot-level code: it never reaches the domain, the application or an adapter. */
    @ArchTest
    static final ArchRule DEVICE_CLI_NEVER_DEPENDS_ON_THE_HEXAGON = noClasses()
            .that().resideInAPackage(DEVICE)
            .should().dependOnClassesThat().resideInAnyPackage(DOMAIN, APPLICATION, INFRASTRUCTURE, API);

    /** The layering as one declaration, so that a layer added later cannot sit outside of it by accident. */
    @ArchTest
    static final ArchRule LAYERING = Architectures.layeredArchitecture()
            .consideringOnlyDependenciesInLayers()
            .layer("Domain").definedBy(DOMAIN)
            .layer("Application").definedBy(APPLICATION)
            .layer("Infrastructure").definedBy(INFRASTRUCTURE)
            .layer("Api").definedBy(API)
            .layer("Boot").definedBy(ROOT)
            .layer("Device").definedBy(DEVICE)
            .whereLayer("Domain").mayOnlyBeAccessedByLayers("Application", "Infrastructure", "Api", "Boot")
            .whereLayer("Application").mayOnlyBeAccessedByLayers("Infrastructure", "Api", "Boot")
            .whereLayer("Infrastructure").mayOnlyBeAccessedByLayers("Boot")
            .whereLayer("Api").mayOnlyBeAccessedByLayers("Boot")
            .whereLayer("Device").mayNotBeAccessedByAnyLayer()
            .allowEmptyShould(true);

    /**
     * Not instantiable: ArchUnit collects the rules from the static fields annotated with {@code @ArchTest}.
     */
    private HexagonalArchitectureTest() {
        // no instance is ever created
    }

    /**
     * Condition met by a class that implements an interface generated from an OpenAPI contract.
     *
     * @return the condition.
     */
    private static ArchCondition<JavaClass> implementAGeneratedApiInterface() {
        return new ArchCondition<>("implement an interface generated from an OpenAPI contract") {
            @Override
            public void check(final JavaClass item, final ConditionEvents events) {
                final var implemented = item.getAllRawInterfaces().stream()
                        .anyMatch(JavaClass.Predicates.resideInAPackage(GENERATED_API));
                events.add(new SimpleConditionEvent(item, implemented,
                        item.getName() + " implements no interface generated from an OpenAPI contract"));
            }
        };
    }
}

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

package com.irurueta.authserver.authorization;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaModifier;
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
import org.springframework.transaction.annotation.Transactional;
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
 * can be checked against the whole class graph.
 */
@AnalyzeClasses(
        packages = "com.irurueta.authserver.authorization",
        importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

    /** Root package of the authorization server. */
    private static final String ROOT = "com.irurueta.authserver.authorization";

    /** Package of the domain layer. */
    private static final String DOMAIN = ROOT + ".domain..";

    /** Package of the application layer. */
    private static final String APPLICATION = ROOT + ".application..";

    /** Package of the infrastructure layer. */
    private static final String INFRASTRUCTURE = ROOT + ".infrastructure..";

    /** Package of the api layer. */
    private static final String API = ROOT + ".api..";

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

    /** A driving adapter never depends on a driven adapter. */
    @ArchTest
    static final ArchRule API_NEVER_DEPENDS_ON_INFRASTRUCTURE = noClasses()
            .that().resideInAPackage(API)
            .should().dependOnClassesThat().resideInAPackage(INFRASTRUCTURE);

    /** A driven adapter never depends on a driving adapter. */
    @ArchTest
    static final ArchRule INFRASTRUCTURE_NEVER_DEPENDS_ON_API = noClasses()
            .that().resideInAPackage(INFRASTRUCTURE)
            .should().dependOnClassesThat().resideInAPackage(API);

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

    /**
     * Every use case demarcates its own transaction, on the class or on each of its public methods: transactions
     * are a use-case concern, so an adapter never has to open one and a port call never runs without one.
     */
    @ArchTest
    static final ArchRule USE_CASES_ARE_TRANSACTIONAL = classes()
            .that().haveSimpleNameEndingWith("UseCase")
            .should(beTransactional());

    /** Classes named {@code *Controller} live in the api layer. */
    @ArchTest
    static final ArchRule CONTROLLERS_LIVE_IN_API = classes()
            .that().haveSimpleNameEndingWith("Controller")
            .should().resideInAPackage(API);

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
            .should(implementAGeneratedApiInterface());

    /** The layering as one declaration, so that a layer added later cannot sit outside of it by accident. */
    @ArchTest
    static final ArchRule LAYERING = Architectures.layeredArchitecture()
            .consideringOnlyDependenciesInLayers()
            .layer("Domain").definedBy(DOMAIN)
            .layer("Application").definedBy(APPLICATION)
            .layer("Infrastructure").definedBy(INFRASTRUCTURE)
            .layer("Api").definedBy(API)
            .layer("Boot").definedBy(ROOT)
            .whereLayer("Domain").mayOnlyBeAccessedByLayers("Application", "Infrastructure", "Api", "Boot")
            .whereLayer("Application").mayOnlyBeAccessedByLayers("Infrastructure", "Api", "Boot")
            .whereLayer("Infrastructure").mayOnlyBeAccessedByLayers("Boot")
            .whereLayer("Api").mayOnlyBeAccessedByLayers("Boot");

    /**
     * Condition met by a class annotated with {@link Transactional}, or whose public methods all are.
     *
     * @return the condition.
     */
    private static ArchCondition<JavaClass> beTransactional() {
        return new ArchCondition<>("be annotated with @Transactional on the class or on every public method") {
            @Override
            public void check(final JavaClass item, final ConditionEvents events) {
                final var transactional = item.isAnnotatedWith(Transactional.class)
                        || item.getMethods().stream()
                        .filter(method -> method.getModifiers().contains(JavaModifier.PUBLIC))
                        .allMatch(method -> method.isAnnotatedWith(Transactional.class));
                events.add(new SimpleConditionEvent(item, transactional,
                        item.getName() + " does not demarcate a transaction"));
            }
        };
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

    /**
     * Not instantiable: ArchUnit collects the rules from the static fields annotated with {@code @ArchTest}.
     */
    private HexagonalArchitectureTest() {
        // no instance is ever created
    }
}

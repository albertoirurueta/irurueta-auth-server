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

package com.irurueta.authserver.bff;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.Architectures;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;

/**
 * Architecture rules of the hexagon, checked at package granularity over the classes of every module. They
 * complement the {@code bannedDependencies} rules that the {@code pom.xml} of each module declares at jar
 * granularity. {@code boot} is the only module that sees every layer, so it is the only place where these rules
 * can be checked against the whole class graph. Layers this application does not have yet (application and
 * infrastructure) are optional, so the rules start applying as soon as they appear.
 */
@AnalyzeClasses(
        packages = "com.irurueta.authserver.bff",
        importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

    /** Root package of the bff. */
    private static final String ROOT = "com.irurueta.authserver.bff";

    /** Package of the domain layer. */
    private static final String DOMAIN = ROOT + ".domain..";

    /** Package of the application layer. */
    private static final String APPLICATION = ROOT + ".application..";

    /** Package of the infrastructure layer. */
    private static final String INFRASTRUCTURE = ROOT + ".infrastructure..";

    /** Package of the api layer. */
    private static final String API = ROOT + ".api..";

    /** Domain depends on nothing but the JDK and Lombok. */
    @ArchTest
    static final ArchRule DOMAIN_DEPENDS_ON_NOTHING_BUT_THE_JDK = classes()
            .that().resideInAPackage(DOMAIN)
            .should().onlyDependOnClassesThat().resideInAnyPackage(DOMAIN, "java..", "javax..", "lombok..")
            .allowEmptyShould(true);

    /** Application depends only on domain (and the JDK and Lombok). */
    @ArchTest
    static final ArchRule APPLICATION_DEPENDS_ONLY_ON_DOMAIN = classes()
            .that().resideInAPackage(APPLICATION)
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                    APPLICATION, DOMAIN, "java..", "javax..", "lombok..")
            .allowEmptyShould(true);

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
            .should().resideInAPackage(APPLICATION)
            .allowEmptyShould(true);

    /** Classes named {@code *Controller} live in the api layer. */
    @ArchTest
    static final ArchRule CONTROLLERS_LIVE_IN_API = classes()
            .that().haveSimpleNameEndingWith("Controller")
            .should().resideInAPackage(API)
            .allowEmptyShould(true);

    /** The layering as one declaration, so that a layer added later cannot sit outside of it by accident. */
    @ArchTest
    static final ArchRule LAYERING = Architectures.layeredArchitecture()
            .consideringOnlyDependenciesInLayers()
            .withOptionalLayers(true)
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
     * Not instantiable: ArchUnit collects the rules from the static fields annotated with {@code @ArchTest}.
     */
    private HexagonalArchitectureTest() {
        // no instance is ever created
    }
}

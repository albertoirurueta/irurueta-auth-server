# irurueta-auth-server

Example OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot and Spring Security,
plus the BFF, resource server and service client that use it.

[![Build and test](https://github.com/albertoirurueta/irurueta-auth-server/actions/workflows/build.yml/badge.svg)](https://github.com/albertoirurueta/irurueta-auth-server/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=albertoirurueta_irurueta-auth-server&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=albertoirurueta_irurueta-auth-server)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=albertoirurueta_irurueta-auth-server&metric=coverage)](https://sonarcloud.io/summary/new_code?id=albertoirurueta_irurueta-auth-server)

This is a teaching example, not a product, and it is never deployed. It backs a step-by-step guide in the
[Irurueta Docs](https://www.irurueta.com) site (*Guides & References → Backend Development → SpringBoot
Reference*), so the guide's code listings come from code here that compiles and passes its tests. The work is
tracked in this repository's issues and the *1.0.0* milestone.

## Project Status

| | |
|---|---|
| Language | Java 21 to 25 (the build enforces `[21,26)`) |
| Build tool | Maven (wrapper included, Maven 3.9) |
| Framework | Spring Boot 4.1.2 (Spring Security and Spring Authorization Server managed by Boot) |
| Current development version | 1.0.0-SNAPSHOT |
| License | Apache License 2.0 |
| CI | GitHub Actions: `clean verify` (every gate, unit, integration and end-to-end tests) on pushes to `main`, `develop` and `release_*`, and on pull requests, then SonarCloud when `SONAR_TOKEN` is set. Never deploys. |
| Quality | Build gates that fail `verify`: Checkstyle, PMD + CPD, SpotBugs, JaCoCo 80% line / 70% branch (aggregated), enforcer and ArchUnit |

## Modules

Each application is hexagonal: one Maven sub-reactor, split into `domain`, `application`,
`infrastructure/<adapter>`, `api/<adapter>` and `boot` modules (a layer exists only once it has code). Dependencies
between layers are enforced by the Maven enforcer (`bannedDependencies`) and by ArchUnit.

| Module | Port | Role |
|---|---|---|
| `auth-server` | 9000 | The authorization server: Spring Authorization Server protocol endpoints, plus the login, consent, MFA and account pages. Modules `domain`, `application`, `infrastructure/persistence`, `infrastructure/keys`, `api/web`, `boot` |
| `bff` | 8080 | Backend-for-Frontend: signs a browser SPA in through `auth-server` and calls `resource-server` on the user's behalf through a generated client, so tokens never reach JavaScript. Modules `domain`, `application`, `infrastructure/session`, `infrastructure/resourceserver`, `api/web`, `boot` |
| `resource-server` | 8081 | JWT-protected API that validates the tokens issued by `auth-server`. Modules `api/web`, `boot` |
| `service-client` | — | Non-interactive client that obtains tokens with the client credentials grant and calls `resource-server`. A single `boot` module |
| `test-support` | — | Shared Testcontainers PostgreSQL harness (`@PostgresIT`) |
| `e2e-tests` | — | Playwright sign-in smoke test against the packaged `auth-server` and `bff` jars |
| `coverage` | — | Aggregates the JaCoCo data of every module and enforces the coverage thresholds |

## Documentation

- Published documentation: <https://albertoirurueta.github.io/irurueta-auth-server/>, with the generated
  [Maven site reports](https://albertoirurueta.github.io/irurueta-auth-server/mvn-site/) (Javadoc, JaCoCo, test, Checkstyle,
  PMD and SpotBugs reports), rebuilt by the *Documentation* workflow on every push to `main`.
- Antora documentation sources: [`docs/`](docs). Build them locally with
  `cd docs && npm ci && npx antora antora-playbook.yml`; the site is written to `docs/build/site`.
- The step-by-step guide built on this example will be published in the [Irurueta Docs](https://www.irurueta.com)
  site.

## Getting Started

### Requirements

- JDK 21 to 25
- Docker, for the integration tests (Testcontainers) and the local services the applications will use

### Build and test

```bash
./mvnw -B clean verify   # unit (*Test) + integration (*IT) + end-to-end tests and every build gate
./mvnw test              # fast unit-test run only: no Spring context, no Docker
./mvnw -pl auth-server/api/web -am test -Dtest=LoginControllerTest   # one test class in one module
./mvnw verify site       # adds the browsable Checkstyle/PMD/SpotBugs/JXR/Javadoc reports
```

`verify` must be green before pushing. Unit tests (`*Test`, Surefire) start no Spring context; every Spring or
Testcontainers test is an integration test (`*IT`, Failsafe). Coverage reports are written to
`<module>/target/site/jacoco*` and aggregated in `coverage/target/site/jacoco-aggregate`.

### Build gates

All of these fail the build:

- **Checkstyle**: `checkstyle.xml`, warnings are errors, test sources included.
- **PMD** and **CPD** (copy-paste detection).
- **SpotBugs**: `threshold=Medium`, `effort=Max`.
- **JaCoCo**: 80% line / 70% branch on the aggregated bundle of the `coverage` module.
- **Enforcer**: Java `[21,26)`, Maven 3.9+ and the hexagonal `bannedDependencies` rules.
- **ArchUnit**: the hexagonal rules in each application's `boot` module.

CI additionally runs the SonarCloud analysis (`./mvnw -B -ntp sonar:sonar`) when the `SONAR_TOKEN` secret is set.

### Run the applications

```bash
./mvnw -pl auth-server/boot -am spring-boot:run -Dspring-boot.run.profiles=dev
./mvnw -pl resource-server/boot -am spring-boot:run
./mvnw -pl bff/boot -am spring-boot:run
./mvnw -pl service-client/boot -am spring-boot:run
```

Start `auth-server` first, each application in its own terminal. The `dev` profile of `auth-server` starts the
services of `compose.yaml` and seeds a demo user and the `bff` client with generated secrets (written to its log).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

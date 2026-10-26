# irurueta-auth-server

Example OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot and Spring Security,
plus the BFF, resource server and service client that use it.

[![Build and test](https://github.com/albertoirurueta/irurueta-auth-server/actions/workflows/build.yml/badge.svg)](https://github.com/albertoirurueta/irurueta-auth-server/actions/workflows/build.yml)

This is a teaching example, not a product, and it is never deployed. It backs a step-by-step guide in the
[Irurueta Docs](https://www.irurueta.com) site (*Guides & References → Backend Development → SpringBoot
Reference*), so the guide's code listings come from code here that compiles and passes its tests. The work is
tracked in this repository's issues and the *1.0.0* milestone. Until it is complete, the modules are skeletons that
only start a Spring Boot application.

## Project Status

| | |
|---|---|
| Language | Java 21 |
| Build tool | Maven (wrapper included, Maven 3.9) |
| Framework | Spring Boot 4.1.2 (Spring Security and Spring Authorization Server managed by Boot) |
| Current development version | 1.0.0-SNAPSHOT |
| License | Apache License 2.0 |
| CI | GitHub Actions: build and test (unit + integration) on pushes to `main`, `develop` and `release_*`, and on pull requests. Never deploys. |
| Quality | JaCoCo coverage on every `verify`; Checkstyle, PMD and SpotBugs reports in `mvn site` (report-only) |

## Modules

| Module | Port | Role |
|---|---|---|
| `auth-server` | 9000 | The authorization server: Spring Authorization Server protocol endpoints, plus the login, consent, MFA and account pages |
| `bff` | 8080 | Backend-for-Frontend: signs a browser SPA in through `auth-server` and relays its API calls, so tokens never reach JavaScript |
| `resource-server` | 8081 | JWT-protected API that validates the tokens issued by `auth-server` |
| `service-client` | — | Non-interactive client that obtains tokens with the client credentials grant and calls `resource-server` |

## Documentation

- Antora documentation sources: [`docs/`](docs). Build them locally with
  `cd docs && npm ci && npx antora antora-playbook.yml`; the site is written to `docs/build/site`.
- The step-by-step guide built on this example will be published in the [Irurueta Docs](https://www.irurueta.com)
  site.

## Getting Started

### Requirements

- JDK 21 or newer
- Docker, for the integration tests (Testcontainers) and the local services the applications will use

### Build and test

```bash
./mvnw verify
```

This runs the unit tests (`*Test`, Surefire) and the integration tests (`*IT`, Failsafe), and writes JaCoCo
coverage reports to `<module>/target/site/jacoco`.

### Run the applications

```bash
./mvnw install -DskipTests
./mvnw -pl auth-server spring-boot:run
./mvnw -pl resource-server spring-boot:run
./mvnw -pl bff spring-boot:run
./mvnw -pl service-client spring-boot:run
```

Start `auth-server` first, each application in its own terminal.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

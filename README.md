# java-dep-audit

Dependency-free **Java 17+** CLI that scans `pom.xml` and `build.gradle(.kts)` files for known-vulnerable libraries (Log4Shell, Spring4Shell, Text4Shell, SnakeYAML, H2, Struts, fastjson and more) and tells you the fixed version.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Build and run

```bash
./build.sh test                                   # javac + built-in test runner, no Maven/Gradle needed
./build.sh && java -cp out/main dev.jvch.depaudit.Main samples
java -cp out/main dev.jvch.depaudit.Main . --json
java -cp out/main dev.jvch.depaudit.Main . --advisories my-rules.tsv
```

Exit code is `2` when something vulnerable is found, so it works as a CI gate.

Sample output:

```
[CRITICAL] org.apache.logging.log4j:log4j-core:2.14.1  CVE-2021-44228  fixed in 2.17.1
    Log4Shell JNDI lookup remote code execution ...
```

## How it works

* **Maven**: XML parsing with DOCTYPE and external entities disabled, so scanning a hostile repository cannot trigger XXE; `${property}` references are resolved (with a loop guard); dependencies without an explicit version are skipped
* **Gradle**: `group:artifact:version` coordinates in Groovy and Kotlin DSL
* **Versions**: Maven-like ordering (`2.10 > 2.9`, `1.0-beta < 1.0-rc < 1.0`, `Final` == release)
* **Rules**: ranges are `[introduced, fixed)`; add your own via a tab-separated file (`group artifact introduced fixed id severity summary`)
* Unresolved version properties are reported as skipped rather than guessed

## Scope and limits

The bundled advisory list is a small curated sample of famous vulnerabilities, **not** a complete database, and it does not resolve transitive dependencies or BOM-managed versions. For real coverage use OSV-Scanner, OWASP Dependency-Check or GitHub Dependabot; this project shows the mechanics and is handy for quick checks and custom internal rules.

MIT licensed.

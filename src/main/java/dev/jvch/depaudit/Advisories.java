package dev.jvch.depaudit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * A small bundled sample of well-known Java vulnerabilities. It is NOT a replacement for OSV, GHSA or OWASP
 * Dependency-Check: use it to demo the idea or to add your own rules via a TSV file.
 */
public final class Advisories {
    private Advisories() {}

    public static List<Advisory> builtin() {
        return List.of(
            new Advisory("org.apache.logging.log4j", "log4j-core", "2.0", "2.17.1", "CVE-2021-44228", "critical", "Log4Shell JNDI lookup remote code execution (and follow-ups CVE-2021-45046, -45105, -44832)"),
            new Advisory("org.springframework", "spring-beans", "5.3.0", "5.3.18", "CVE-2022-22965", "critical", "Spring4Shell data binding remote code execution on JDK 9+"),
            new Advisory("org.springframework", "spring-beans", "5.2.0", "5.2.20", "CVE-2022-22965", "critical", "Spring4Shell data binding remote code execution on JDK 9+"),
            new Advisory("org.apache.commons", "commons-text", "1.5", "1.10.0", "CVE-2022-42889", "critical", "Text4Shell: unsafe interpolation (script, dns, url lookups)"),
            new Advisory("commons-collections", "commons-collections", "3.0", "3.2.2", "CVE-2015-7501", "high", "Deserialization gadget chains leading to remote code execution"),
            new Advisory("org.yaml", "snakeyaml", "0.0", "2.0", "CVE-2022-1471", "high", "Unsafe deserialization via the default Constructor"),
            new Advisory("com.alibaba", "fastjson", "0.0", "1.2.83", "CVE-2022-25845", "high", "Deserialization bypass allowing remote code execution"),
            new Advisory("com.h2database", "h2", "1.4.198", "2.0.206", "CVE-2021-42392", "critical", "JNDI remote code execution through the console and URLs"),
            new Advisory("com.thoughtworks.xstream", "xstream", "0.0", "1.4.20", "CVE-2022-41966", "high", "Denial of service via crafted XML (stack overflow)"),
            new Advisory("org.apache.struts", "struts2-core", "2.0.0", "2.5.33", "CVE-2023-50164", "critical", "Path traversal in file upload leading to remote code execution")
        );
    }

    /** Load extra rules from TSV: group, artifact, introduced, fixed, id, severity, summary (tab separated, # comments). */
    public static List<Advisory> fromTsv(Path file) throws IOException {
        List<Advisory> out = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split("\t", -1);
            if (f.length < 7) throw new IOException("expected 7 tab-separated fields: " + line);
            out.add(new Advisory(f[0], f[1], f[2], f[3], f[4], f[5], f[6]));
        }
        return out;
    }
}

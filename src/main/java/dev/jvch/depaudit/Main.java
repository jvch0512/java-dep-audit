package dev.jvch.depaudit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public final class Main {
    private Main() {}

    public static void main(String[] args) throws IOException {
        System.exit(run(args));
    }

    static int run(String[] args) throws IOException {
        Path root = Path.of(".");
        Path extra = null;
        boolean json = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--advisories" -> extra = Path.of(args[++i]);
                case "--json" -> json = true;
                case "-h", "--help" -> { System.out.println("usage: java-dep-audit [dir] [--advisories file.tsv] [--json]"); return 0; }
                default -> root = Path.of(args[i]);
            }
        }
        List<Dependency> deps = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                String n = p.getFileName().toString();
                if (p.toString().contains("/.git/") || p.toString().contains("/node_modules/")) continue;
                if (n.equals("pom.xml")) deps.addAll(Parsers.pom(Files.readString(p), p.toString()));
                else if (n.equals("build.gradle") || n.equals("build.gradle.kts")) deps.addAll(Parsers.gradle(Files.readString(p), p.toString()));
            }
        }
        List<Advisory> adv = new ArrayList<>(Advisories.builtin());
        if (extra != null) adv.addAll(Advisories.fromTsv(extra));
        List<Auditor.Finding> findings = Auditor.audit(deps, adv);
        if (json) {
            StringBuilder sb = new StringBuilder("[\n");
            for (int i = 0; i < findings.size(); i++) {
                Auditor.Finding f = findings.get(i);
                sb.append(String.format("  {\"dependency\":\"%s:%s:%s\",\"id\":\"%s\",\"severity\":\"%s\",\"fixed\":\"%s\",\"file\":\"%s\"}%s%n",
                    esc(f.dep().group()), esc(f.dep().artifact()), esc(f.dep().version()), esc(f.advisory().id()), esc(f.advisory().severity()),
                    esc(f.advisory().fixed()), esc(f.dep().source()), i + 1 < findings.size() ? "," : ""));
            }
            System.out.println(sb.append("]"));
        } else {
            for (Auditor.Finding f : findings) {
                System.out.printf("[%-8s] %s:%s:%s  %s  fixed in %s%n    %s (%s)%n", f.advisory().severity().toUpperCase(), f.dep().group(), f.dep().artifact(),
                    f.dep().version(), f.advisory().id(), f.advisory().fixed(), f.advisory().summary(), f.dep().source());
            }
            System.out.printf("%d dependencies checked, %d vulnerable%n", deps.size(), findings.size());
        }
        return findings.isEmpty() ? 0 : 2;
    }

    private static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }
}

package dev.jvch.depaudit;

import java.util.ArrayList;
import java.util.List;

public final class Auditor {
    public record Finding(Dependency dep, Advisory advisory) {}

    private Auditor() {}

    public static List<Finding> audit(List<Dependency> deps, List<Advisory> advisories) {
        List<Finding> out = new ArrayList<>();
        for (Dependency d : deps) {
            if (d.version().contains("${")) continue; // unresolved property: cannot judge
            Version v = new Version(d.version());
            for (Advisory a : advisories) {
                if (a.affects(d.group(), d.artifact(), v)) out.add(new Finding(d, a));
            }
        }
        return out;
    }
}

package dev.jvch.depaudit;

/** A vulnerable range [introduced, fixed) for group:artifact. */
public record Advisory(String group, String artifact, String introduced, String fixed, String id, String severity, String summary) {
    public boolean affects(String g, String a, Version v) {
        if (!group.equals(g) || !artifact.equals(a)) return false;
        return v.compareTo(new Version(introduced)) >= 0 && v.compareTo(new Version(fixed)) < 0;
    }
}

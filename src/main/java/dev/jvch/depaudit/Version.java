package dev.jvch.depaudit;

import java.util.ArrayList;
import java.util.List;

/** Maven-ish version ordering: numeric segments first, pre-release qualifiers sort before the release. */
public final class Version implements Comparable<Version> {
    private final String raw;
    private final List<Integer> nums = new ArrayList<>();
    private final String qualifier;

    public Version(String raw) {
        this.raw = raw.trim();
        String[] dash = this.raw.split("[-_]", 2);
        for (String p : dash[0].split("\\.")) {
            String digits = p.replaceAll("[^0-9].*$", "");
            nums.add(digits.isEmpty() ? 0 : Integer.parseInt(digits.length() > 9 ? digits.substring(0, 9) : digits));
        }
        String q = dash.length > 1 ? dash[1].toLowerCase() : "";
        if (q.equals("final") || q.equals("release") || q.equals("ga")) q = "";
        this.qualifier = q;
    }

    private static int rank(String q) {
        if (q.isEmpty()) return 3;
        if (q.startsWith("snapshot")) return 0;
        if (q.startsWith("alpha") || q.startsWith("a")) return 0;
        if (q.startsWith("beta") || q.startsWith("b")) return 1;
        if (q.startsWith("rc") || q.startsWith("cr") || q.startsWith("m")) return 2;
        return 3;
    }

    @Override
    public int compareTo(Version o) {
        int n = Math.max(nums.size(), o.nums.size());
        for (int i = 0; i < n; i++) {
            int a = i < nums.size() ? nums.get(i) : 0;
            int b = i < o.nums.size() ? o.nums.get(i) : 0;
            if (a != b) return Integer.compare(a, b);
        }
        int r = Integer.compare(rank(qualifier), rank(o.qualifier));
        return r != 0 ? r : qualifier.compareTo(o.qualifier);
    }

    @Override public boolean equals(Object o) { return o instanceof Version v && compareTo(v) == 0; }
    @Override public int hashCode() { return nums.hashCode() * 31 + qualifier.hashCode(); }
    @Override public String toString() { return raw; }
}

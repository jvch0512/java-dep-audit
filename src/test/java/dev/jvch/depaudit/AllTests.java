package dev.jvch.depaudit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Tiny dependency-free test runner. Run with assertions enabled (-ea). */
public final class AllTests {
    private static int passed = 0;

    private interface Case { void run() throws Exception; }

    private static void test(String name, Case c) {
        try {
            c.run();
            passed++;
            System.out.println("ok   " + name);
        } catch (Throwable t) {
            System.out.println("FAIL " + name + ": " + t);
            System.exit(1);
        }
    }

    private static void eq(Object a, Object b) { if (!a.equals(b)) throw new AssertionError(a + " != " + b); }
    private static void yes(boolean c, String msg) { if (!c) throw new AssertionError(msg); }

    private static final String POM = """
        <project>
          <version>1.0.0</version>
          <properties><log4j.version>2.14.1</log4j.version><snake>1.33</snake></properties>
          <dependencies>
            <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
            <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${snake}</version></dependency>
            <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version></dependency>
            <dependency><groupId>no.version</groupId><artifactId>managed</artifactId></dependency>
          </dependencies>
        </project>""";

    public static void main(String[] args) throws Exception {
        test("version ordering", () -> {
            yes(new Version("2.14.1").compareTo(new Version("2.17.1")) < 0, "2.14.1 < 2.17.1");
            yes(new Version("2.10").compareTo(new Version("2.9")) > 0, "numeric not lexical");
            yes(new Version("1.0-beta1").compareTo(new Version("1.0")) < 0, "beta before release");
            yes(new Version("1.0-rc1").compareTo(new Version("1.0-beta2")) > 0, "rc after beta");
            yes(new Version("1.0.Final").compareTo(new Version("1.0")) == 0, "Final equals release");
            yes(new Version("1.2").compareTo(new Version("1.2.0")) == 0, "trailing zero");
        });
        test("range boundaries are [introduced, fixed)", () -> {
            Advisory a = Advisories.builtin().get(0);
            yes(a.affects(a.group(), a.artifact(), new Version("2.14.1")), "2.14.1 vulnerable");
            yes(a.affects(a.group(), a.artifact(), new Version("2.17.0")), "2.17.0 vulnerable");
            yes(!a.affects(a.group(), a.artifact(), new Version("2.17.1")), "2.17.1 fixed");
            yes(!a.affects(a.group(), a.artifact(), new Version("1.2.17")), "1.x is outside the range");
            yes(!a.affects("other", a.artifact(), new Version("2.14.1")), "other group");
        });
        test("pom parsing resolves properties and skips unversioned deps", () -> {
            List<Dependency> d = Parsers.pom(POM, "pom.xml");
            eq(d.size(), 3);
            eq(d.get(0).version(), "2.14.1");
            eq(d.get(1).version(), "1.33");
        });
        test("pom parser blocks XXE and DOCTYPE", () -> {
            String evil = "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><project>&x;</project>";
            try { Parsers.pom(evil, "evil/pom.xml"); throw new AssertionError("should have been rejected"); }
            catch (IOException expected) { yes(expected.getMessage().contains("evil/pom.xml"), "error mentions file"); }
        });
        test("gradle parsing (groovy and kotlin DSL)", () -> {
            List<Dependency> d = Parsers.gradle("implementation 'org.yaml:snakeyaml:1.30'\nimplementation(\"com.h2database:h2:2.0.202\")\ntestImplementation 'junit:junit:4.13'", "build.gradle");
            eq(d.size(), 3);
            eq(d.get(1).artifact(), "h2");
        });
        test("audit reports only vulnerable dependencies", () -> {
            List<Auditor.Finding> f = Auditor.audit(Parsers.pom(POM, "pom.xml"), Advisories.builtin());
            eq(f.size(), 2);
            eq(f.get(0).advisory().id(), "CVE-2021-44228");
            eq(f.get(1).advisory().id(), "CVE-2022-1471");
        });
        test("unresolved property is skipped, not guessed", () -> {
            List<Auditor.Finding> f = Auditor.audit(List.of(new Dependency("org.yaml", "snakeyaml", "${unknown}", "x")), Advisories.builtin());
            eq(f.size(), 0);
        });
        test("custom TSV advisories", () -> {
            Path t = Files.createTempFile("adv", ".tsv");
            Files.writeString(t, "# comment\ncom.acme\tlib\t1.0\t1.5\tACME-1\thigh\tdemo\n");
            List<Advisory> a = Advisories.fromTsv(t);
            eq(a.size(), 1);
            yes(a.get(0).affects("com.acme", "lib", new Version("1.4")), "custom rule applies");
            Files.writeString(t, "too\tfew\tfields\n");
            try { Advisories.fromTsv(t); throw new AssertionError("should reject"); } catch (IOException expected) { }
        });
        test("end to end exit code", () -> {
            Path dir = Files.createTempDirectory("proj");
            Files.writeString(dir.resolve("pom.xml"), POM);
            eq(Main.run(new String[] {dir.toString()}), 2);
            Files.writeString(dir.resolve("pom.xml"), "<project><dependencies></dependencies></project>");
            eq(Main.run(new String[] {dir.toString()}), 0);
        });
        System.out.println(passed + " tests passed");
    }
}

package dev.jvch.depaudit;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** Extract dependencies from pom.xml and Gradle build files. */
public final class Parsers {
    private Parsers() {}

    /** Parse a pom with XXE disabled: build files from untrusted repositories must never trigger network or file access. */
    public static List<Dependency> pom(String xml, String source) throws IOException {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            DocumentBuilder b = f.newDocumentBuilder();
            Document doc = b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            Map<String, String> props = new HashMap<>();
            Element root = doc.getDocumentElement();
            NodeList propsNodes = root.getElementsByTagName("properties");
            for (int i = 0; i < propsNodes.getLength(); i++) {
                for (Node n = propsNodes.item(i).getFirstChild(); n != null; n = n.getNextSibling()) {
                    if (n instanceof Element e) props.put(e.getTagName(), e.getTextContent().trim());
                }
            }
            String projectVersion = text(root, "version");
            if (projectVersion != null) props.put("project.version", projectVersion);
            List<Dependency> out = new ArrayList<>();
            NodeList deps = root.getElementsByTagName("dependency");
            for (int i = 0; i < deps.getLength(); i++) {
                Element d = (Element) deps.item(i);
                String g = text(d, "groupId"), a = text(d, "artifactId"), v = text(d, "version");
                if (g == null || a == null || v == null) continue;
                out.add(new Dependency(resolve(g, props), resolve(a, props), resolve(v, props), source));
            }
            return out;
        } catch (Exception e) {
            throw new IOException("cannot parse " + source + ": " + e.getMessage(), e);
        }
    }

    private static String text(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && e.getTagName().equals(tag)) return e.getTextContent().trim();
        }
        return null;
    }

    static String resolve(String value, Map<String, String> props) {
        String prev;
        int guard = 0;
        do {
            prev = value;
            Matcher m = Pattern.compile("\\$\\{([^}]+)}").matcher(value);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String r = props.get(m.group(1));
                m.appendReplacement(sb, Matcher.quoteReplacement(r != null ? r : m.group()));
            }
            m.appendTail(sb);
            value = sb.toString();
        } while (!value.equals(prev) && ++guard < 10);
        return value;
    }

    private static final Pattern GRADLE = Pattern.compile("[\"']([\\w.\\-]+):([\\w.\\-]+):([\\w.\\-]+)[\"']");

    public static List<Dependency> gradle(String text, String source) {
        List<Dependency> out = new ArrayList<>();
        Matcher m = GRADLE.matcher(text);
        while (m.find()) out.add(new Dependency(m.group(1), m.group(2), m.group(3), source));
        return out;
    }
}

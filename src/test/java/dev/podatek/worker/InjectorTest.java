package dev.podatek.worker;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static dev.podatek.worker.TestClassLoaders.field;
import static dev.podatek.worker.TestClassLoaders.invokeStaticLoad;
import static org.junit.jupiter.api.Assertions.*;

class InjectorTest {

    private static InjectConfig demoCfg() {
        return new InjectConfig("https://auth4.podatek.dev/api/license", "demo",
                Map.of("k1", "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="), "k1", "license.key");
    }

    private static int major(byte[] cls) {
        return ((cls[6] & 0xFF) << 8) | (cls[7] & 0xFF);
    }

    @Test void injectProducesLoadableWatermarkableJar() throws Exception {
        byte[] master = Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML);
        Injector.Result r = Injector.inject(master, demoCfg());

        assertEquals("shim", r.hookMode);
        assertEquals("1.0.0", r.clientVersion);
        assertNotNull(r.buildId);

        JarModel out = JarModel.read(r.jar);
        // main repointed to shim
        assertTrue(out.descriptor().rawYaml.contains(r.relocPrefix));
        assertEquals(r.relocPrefix + ".LicenseShim", out.descriptor().mainClass);
        // the rest of plugin.yml preserved
        assertEquals("Demo", out.descriptor().name);
        // payload present, no un-relocated client classes
        assertTrue(out.entries().keySet().stream().anyMatch(k -> k.startsWith(r.relocPrefix + "/")));
        assertFalse(out.entries().containsKey("dev/podatek/lic/PodatekLicense.class"));
        // bytecode major 52 on a synthesized class
        assertEquals(52, major(out.entries().get(r.relocPrefix + "/LicenseShim.class")));

        // GeneratedConfig.load() from the assembled jar returns injected values
        Map<String, byte[]> all = new HashMap<>(out.entries());
        Object loaded = invokeStaticLoad(all, r.relocPrefix + ".GeneratedConfig");
        assertEquals("https://auth4.podatek.dev/api/license", field(loaded, "baseUrl"));
        assertEquals("demo", field(loaded, "pluginId"));

        // the shim links + verifies against the real relocated PodatekLicense in the jar
        Class.forName(r.relocPrefix + ".LicenseShim", false, TestClassLoaders.loader(out.entries()));
    }

    @Test void noPluginYmlIsClientError() {
        byte[] jar = JarModelTestSupport.jarOf(Map.of(
                "com/demo/DemoPlugin.class",
                Fixtures.pluginClass("com/demo/DemoPlugin", false, false)));
        InjectException ex = assertThrows(InjectException.class, () -> Injector.inject(jar, demoCfg()));
        assertEquals(400, ex.status());
    }
}

package dev.podatek.worker;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JarModelTest {

    @Test void readsMainFromPluginYml() {
        byte[] jar = Fixtures.pluginJar("com.demo.DemoPlugin",
                "name: Demo\nversion: 1.0.0\nmain: com.demo.DemoPlugin\n");
        JarModel m = JarModel.read(jar);
        assertEquals("com.demo.DemoPlugin", m.descriptor().mainClass);
        assertEquals("Demo", m.descriptor().name);
        assertTrue(m.descriptor().hasClassicMain);
        assertTrue(m.entries().containsKey("com/demo/DemoPlugin.class"));
    }

    @Test void roundTripsBytes() {
        byte[] jar = Fixtures.pluginJar("com.demo.DemoPlugin",
                "name: Demo\nversion: 1\nmain: com.demo.DemoPlugin\n");
        JarModel m = JarModel.read(jar);
        assertTrue(JarModel.read(m.toBytes()).entries().containsKey("plugin.yml"));
        assertTrue(JarModel.read(m.toBytes()).entries().containsKey("com/demo/DemoPlugin.class"));
    }

    @Test void missingPluginYmlYieldsNullMain() {
        byte[] jar = Fixtures.jar("com/demo/DemoPlugin",
                Fixtures.pluginClass("com/demo/DemoPlugin", false, false),
                "not-a-plugin-yml: true\n");
        // no plugin.yml entry -> use a jar without it
        java.util.Map<String, byte[]> only = new java.util.LinkedHashMap<>();
        only.put("com/demo/DemoPlugin.class",
                Fixtures.pluginClass("com/demo/DemoPlugin", false, false));
        JarModel m = JarModel.read(JarModelTestSupport.jarOf(only));
        assertNull(m.descriptor().mainClass);
        assertFalse(m.descriptor().hasClassicMain);
    }
}

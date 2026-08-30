package dev.podatek.worker;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HookerTest {

    private static int major(byte[] cls) {
        return ((cls[6] & 0xFF) << 8) | (cls[7] & 0xFF);
    }

    private static MethodNode method(byte[] cls, String name) {
        ClassNode cn = new ClassNode();
        new ClassReader(cls).accept(cn, 0);
        for (MethodNode m : cn.methods) if (m.name.equals(name)) return m;
        return null;
    }

    /** Index of the first MethodInsn matching owner/name, or -1. */
    private static int indexOfCall(MethodNode m, String owner, String name) {
        int i = 0;
        for (AbstractInsnNode n = m.instructions.getFirst(); n != null; n = n.getNext(), i++) {
            if (n instanceof MethodInsnNode mi && mi.owner.equals(owner) && mi.name.equals(name)) return i;
        }
        return -1;
    }

    /** Load + link + verify the class bytes with a fake PodatekLicense and real bukkit on classpath. */
    private static void loadAndVerify(Map<String, byte[]> extra, String binaryName) throws Exception {
        Map<String, byte[]> all = new HashMap<>(extra);
        // Fake relocated PodatekLicense so INVOKESTATIC resolves during verification.
        all.put("p7/PodatekLicense", FakeLicense.bytes("p7/PodatekLicense"));
        TestClassLoaders.ByteArrayClassLoader cl = TestClassLoaders.loader(all);
        Class.forName(binaryName, false, cl); // load + link + verify, no instantiation
    }

    @Test void shimModeCallsInitThenSuperOnEnable() throws Exception {
        JarModel host = JarModel.read(Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML));
        Hooker.HookResult r = Hooker.hook(host, "p7");

        assertEquals("shim", r.mode);
        assertEquals("p7.LicenseShim", r.newMainClass);
        byte[] shim = r.addedOrPatched().get("p7/LicenseShim.class");
        assertNotNull(shim);
        assertEquals(52, major(shim));

        MethodNode onEnable = method(shim, "onEnable");
        assertNotNull(onEnable);
        int init = indexOfCall(onEnable, "p7/PodatekLicense", "init");
        int superEnable = indexOfCall(onEnable, "com/demo/DemoPlugin", "onEnable");
        assertTrue(init >= 0, "onEnable must call PodatekLicense.init");
        assertTrue(superEnable > init, "init must run before super.onEnable");

        MethodNode onDisable = method(shim, "onDisable");
        assertNotNull(onDisable);
        assertTrue(indexOfCall(onDisable, "p7/PodatekLicense", "shutdown") >= 0,
                "onDisable must call PodatekLicense.shutdown");

        // The whole set (host + shim) must load, link and verify.
        Map<String, byte[]> set = new HashMap<>(host.entries());
        set.putAll(r.addedOrPatched());
        loadAndVerify(set, "p7.LicenseShim");
    }

    @Test void fallbackInsertsIntoFinalMain() throws Exception {
        JarModel host = JarModel.read(Fixtures.finalMainPluginJar());
        Hooker.HookResult r = Hooker.hook(host, "p7");

        assertEquals("asm-insert", r.mode);
        assertEquals("com.demo.DemoPlugin", r.newMainClass);
        byte[] patched = r.addedOrPatched().get("com/demo/DemoPlugin.class");
        assertNotNull(patched);
        assertEquals(52, major(patched));

        MethodNode onEnable = method(patched, "onEnable");
        assertNotNull(onEnable, "fallback must synthesize onEnable if absent");
        assertTrue(indexOfCall(onEnable, "p7/PodatekLicense", "init") >= 0,
                "patched onEnable must call PodatekLicense.init");

        Map<String, byte[]> set = new HashMap<>(host.entries());
        set.putAll(r.addedOrPatched());
        loadAndVerify(set, "com.demo.DemoPlugin");
    }
}

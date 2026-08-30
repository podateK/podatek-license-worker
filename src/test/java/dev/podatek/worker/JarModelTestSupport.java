package dev.podatek.worker;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class JarModelTestSupport {
    private JarModelTestSupport() {}
    static byte[] jarOf(Map<String, byte[]> entries) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(bos)) {
                for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                    zos.putNextEntry(new ZipEntry(e.getKey()));
                    zos.write(e.getValue());
                    zos.closeEntry();
                }
            }
            return bos.toByteArray();
        } catch (Exception ex) { throw new RuntimeException(ex); }
    }
}

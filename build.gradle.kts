plugins {
    application
    id("com.gradleup.shadow") version "8.3.6"
}
group = "dev.podatek"
version = "1.0.0"
java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }
application { mainClass.set("dev.podatek.worker.Main") }
repositories {
    mavenCentral()
    maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")
}
dependencies {
    implementation("org.ow2.asm:asm:9.7")
    implementation("org.ow2.asm:asm-commons:9.7") // ClassRemapper, Remapper
    implementation("io.javalin:javalin:6.3.0")
    implementation("org.yaml:snakeyaml:2.3")
    implementation("org.slf4j:slf4j-simple:2.0.16")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    // Plan 3 client — baked in, its classes are the injection payload.
    implementation(files("libs/podatek-license-client-1.0.0.jar"))
    // Bukkit API only for tests (fixture plugin extends JavaPlugin).
    testImplementation("org.spigotmc:spigot-api:1.16.5-R0.1-SNAPSHOT")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
tasks.test { useJUnitPlatform(); testLogging { events("passed","skipped","failed") } }

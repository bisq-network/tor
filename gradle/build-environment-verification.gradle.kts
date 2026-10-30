import org.gradle.api.GradleException
import org.gradle.api.provider.Provider

val expectedBuildJavaVersion = providers.gradleProperty("releaseBuild.javaVersion")
val expectedBuildJavaVendor = providers.gradleProperty("releaseBuild.javaVendor")
val expectedBuildGradleVersion = providers.gradleProperty("releaseBuild.gradleVersion")

val verifyBuildEnvironmentTask = tasks.register("verifyBuildEnvironment") {
    group = "verification"
    description = "Verifies the local Gradle and Java runtime match the pinned build environment."

    inputs.property("expectedBuildJavaVersion", expectedBuildJavaVersion.orElse(""))
    inputs.property("expectedBuildJavaVendor", expectedBuildJavaVendor.orElse(""))
    inputs.property("expectedBuildGradleVersion", expectedBuildGradleVersion.orElse(""))
    outputs.upToDateWhen { false }
    // Copies of the values of the script, which the configuration cache cannot store. A configuration cache entry
    // belongs to one Gradle version.
    val javaVersionProperty = expectedBuildJavaVersion
    val javaVendorProperty = expectedBuildJavaVendor
    val gradleVersionProperty = expectedBuildGradleVersion
    val actualGradleVersion = gradle.gradleVersion

    doLast {
        fun requiredBuildEnvironmentProperty(propertyName: String, property: Provider<String>): String {
            val value = property.orNull?.trim()
            if (value.isNullOrEmpty()) {
                throw GradleException("Missing $propertyName in gradle.properties")
            }
            return value
        }

        // A build suffix such as +9 would not be compared, so the pin may only hold the numbers of the update.
        fun pinnedVersionNumbers(pin: String): List<Int> {
            val version = runCatching { Runtime.Version.parse(pin) }.getOrNull()
            if (version == null || version.pre().isPresent || version.build().isPresent || version.optional().isPresent) {
                throw GradleException("releaseBuild.javaVersion must be a Java update such as 21.0.13, but is $pin")
            }
            return version.version()
        }

        val expectedJavaVersion = requiredBuildEnvironmentProperty("releaseBuild.javaVersion", javaVersionProperty)
        val expectedJavaVendor = requiredBuildEnvironmentProperty("releaseBuild.javaVendor", javaVendorProperty)
        val expectedGradleVersion = requiredBuildEnvironmentProperty("releaseBuild.gradleVersion", gradleVersionProperty)
        val expectedJavaVersionNumbers = pinnedVersionNumbers(expectedJavaVersion)
        val actualJavaVersion = Runtime.version()
        val actualJavaVendor = System.getProperty("java.vendor")
        val actualJavaVendorVersion = System.getProperty("java.vendor.version")
        val violations = mutableListOf<String>()

        // Azul builds a Java update more than once, for example 21.0.13 as 21.0.13+9 and as 21.0.13.0.3+1, and an
        // installer may offer only the latest. The builds differ in their runtime, which this build does not ship, but
        // compile the same classes, so every build of the update passes.
        if (actualJavaVersion.version().take(expectedJavaVersionNumbers.size) != expectedJavaVersionNumbers) {
            violations += "Java version expected a build of $expectedJavaVersion but was $actualJavaVersion"
        }
        if (actualJavaVendor != expectedJavaVendor) {
            violations += "Java vendor expected $expectedJavaVendor but was $actualJavaVendor"
        }
        if (actualGradleVersion != expectedGradleVersion) {
            violations += "Gradle version expected $expectedGradleVersion but was $actualGradleVersion"
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Build environment verification failed:\n" +
                        violations.joinToString("\n") { "  - $it" }
            )
        }

        // The build of the JDK is not checked, so the log names it
        logger.lifecycle(
            "Verified build environment: Gradle $actualGradleVersion, Java $actualJavaVersion " +
                    "(${listOfNotNull(actualJavaVendor, actualJavaVendorVersion).joinToString(", ")})."
        )
    }
}

tasks.register("verifyReleaseEnvironment") {
    group = "verification"
    description = "Verifies the local Gradle and Java runtime match the pinned release build environment."
    dependsOn(verifyBuildEnvironmentTask)
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(verifyBuildEnvironmentTask)
}

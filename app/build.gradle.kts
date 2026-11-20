import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    id("com.android.application") version "8.11.2"
}


abstract class BuildFirewallEngine @Inject constructor(private val executor: ExecOperations) : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sourceDirectory: DirectoryProperty

    @get:Input
    abstract val ndkPath: Property<String>

    @get:Input
    abstract val goCommand: Property<String>

    @get:OutputDirectory
    abstract val jniDirectory: DirectoryProperty

    @TaskAction
    fun compileEngine() {
        val os = System.getProperty("os.name").lowercase()
        val host = when {
            os.startsWith("windows") -> "windows-x86_64"
            os.startsWith("mac") -> "darwin-x86_64"
            else -> "linux-x86_64"
        }
        val clang = File(ndkPath.get(), "toolchains/llvm/prebuilt/$host/bin/clang" +
                if (os.startsWith("windows")) ".exe" else "")
        if (!clang.isFile) {
            throw GradleException("Android NDK Clang not found. Set FIREWALL_NDK_HOME to the NDK root.")
        }

        val outputs = jniDirectory.get().asFile
        for ((abi, goArch, target) in listOf(
            Triple("arm64-v8a", "arm64", "aarch64-linux-android29"),
            Triple("x86_64", "amd64", "x86_64-linux-android29")
        )) {
            val temporaryLibrary = temporaryDir.resolve(abi).resolve("libfirewall_vpn.so")
            temporaryLibrary.parentFile.mkdirs()
            executor.exec {
                workingDir(sourceDirectory.get().asFile)
                environment("GOOS", "android")
                environment("GOARCH", goArch)
                environment("CGO_ENABLED", "1")
                environment("GOTOOLCHAIN", "local")
                environment("CC", "\"${clang.absolutePath}\"")
                environment("CGO_CFLAGS", "--target=$target")
                environment("CGO_LDFLAGS", "--target=$target -Wl,-z,max-page-size=16384")
                commandLine(goCommand.get(), "build", "-buildvcs=false", "-mod=readonly", "-buildmode=c-shared", "-trimpath",
                    "-ldflags=-s -w", "-o", temporaryLibrary.absolutePath, ".")
            }
            temporaryLibrary.copyTo(outputs.resolve(abi).resolve(temporaryLibrary.name), overwrite = true)
        }
    }
}

// SHA-256 of the distribution certificate introduced in Firewall 0.2.1.
val expectedCertificateSha256 = "c86924bd6ee0509b8b3efd27e4506e8bbba2292887545461f5b95dc7fafb68eb"

val signingStore = providers.environmentVariable("FIREWALL_SIGNING_STORE_FILE").orNull?.let(rootProject::file)
val signingStorePassword = providers.environmentVariable("FIREWALL_SIGNING_STORE_PASSWORD").orNull
val signingKeyAlias = providers.environmentVariable("FIREWALL_SIGNING_KEY_ALIAS").orNull
val signingKeyPassword = providers.environmentVariable("FIREWALL_SIGNING_KEY_PASSWORD").orNull

val verifyFirewallSigning by tasks.registering {
    group = "verification"
    description = "Verifies that the APK will use the original Firewall signing certificate."

    doLast {
        if (signingStore == null || signingStorePassword.isNullOrEmpty()
                || signingKeyAlias.isNullOrEmpty() || signingKeyPassword.isNullOrEmpty()) {
            throw GradleException("Set all FIREWALL_SIGNING_* variables before building an APK. See README.md.")
        }
        if (!signingStore.isFile) {
            throw GradleException("The Firewall signing keystore was not found. Check FIREWALL_SIGNING_STORE_FILE.")
        }

        val entry = try {
            val keystore = KeyStore.getInstance(signingStore, signingStorePassword.toCharArray())
            keystore.getEntry(signingKeyAlias, KeyStore.PasswordProtection(signingKeyPassword.toCharArray()))
        } catch (_: IOException) {
            throw GradleException("Unable to open the Firewall signing keystore. Check the file and store password.")
        } catch (_: GeneralSecurityException) {
            throw GradleException("Unable to read the Firewall signing key. Check the keystore, key alias and key password.")
        }
        if (entry !is KeyStore.PrivateKeyEntry) {
            throw GradleException("The configured Firewall signing alias must contain a private key.")
        }

        val fingerprint = MessageDigest.getInstance("SHA-256").digest(entry.certificate.encoded)
        val certificateSha256 = fingerprint.joinToString("") { "%02x".format(it) }
        if (certificateSha256 != expectedCertificateSha256) {
            throw GradleException("Wrong Firewall signing certificate (SHA-256: $certificateSha256). Use the persistent Firewall distribution key.")
        }
    }
}

android {
    namespace = "ru.firewall"
    compileSdk = 36
    ndkVersion = "28.1.13356709"

    defaultConfig {
        applicationId = "ru.firewall"
        minSdk = 29
        targetSdk = 36
        versionCode = 4
        versionName = "0.2.1"
    }

    val firewallSigning = signingConfigs.create("firewall") {
        storeFile = signingStore
        storePassword = signingStorePassword
        keyAlias = signingKeyAlias
        keyPassword = signingKeyPassword
    }
    buildTypes.configureEach {
        signingConfig = firewallSigning
    }

    packaging {
        jniLibs.keepDebugSymbols.add("**/libfirewall_vpn.so")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

val buildFirewallEngine by tasks.registering(BuildFirewallEngine::class) {
    sourceDirectory.set(rootProject.layout.projectDirectory.dir("vpn-engine"))
    ndkPath.set(providers.environmentVariable("FIREWALL_NDK_HOME").orElse(
        androidComponents.sdkComponents.ndkDirectory.map { it.asFile.absolutePath }))
    goCommand.set(providers.environmentVariable("FIREWALL_GO").orElse("go"))
}

androidComponents.onVariants { variant ->
    variant.sources.jniLibs?.addGeneratedSourceDirectory(buildFirewallEngine, BuildFirewallEngine::jniDirectory)
}

tasks.matching {
    it.name.startsWith("validateSigning") || it.name in setOf("packageDebug", "packageRelease")
}.configureEach {
    dependsOn(verifyFirewallSigning)
}

dependencies {
    implementation(project(":policy"))
    testImplementation("junit:junit:4.13.2")
}

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest

plugins {
    id("com.android.application") version "8.11.2"
}

// SHA-256 of the signing certificate on Firewall_0.1.0_debug.apk.
val expectedCertificateSha256 = "4854a78d51db54d4ccb43eb33d1642718fc591288c20d255b57c9c91a6077f69"

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
            throw GradleException("Wrong Firewall signing certificate (SHA-256: $certificateSha256). Use the key for version 0.1.0.")
        }
    }
}

android {
    namespace = "ru.firewall"
    compileSdk = 36

    defaultConfig {
        applicationId = "ru.firewall"
        minSdk = 29
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.1"
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.matching {
    it.name.startsWith("validateSigning") || it.name in setOf("packageDebug", "packageRelease")
}.configureEach {
    dependsOn(verifyFirewallSigning)
}

dependencies {
    implementation(project(":policy"))
}

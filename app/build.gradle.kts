plugins {
    id("com.android.application") version "8.11.2"
}

android {
    namespace = "ru.firewall"
    compileSdk = 36

    defaultConfig {
        applicationId = "ru.firewall"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":policy"))
}

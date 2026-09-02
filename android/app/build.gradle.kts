plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "net.webshark"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.webshark"
        // 28 is where bionic grew iconv, which glib needs and which decides what
        // Dockerfile.android can build against - see the comment on API there.
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1"
        ndk { abiFilters += "arm64-v8a" }
    }

    packaging {
        jniLibs {
            // The whole reason the two programs are named lib*.so: this is
            // android:extractNativeLibs="true", and an app may only execute a
            // file out of the directory those are unpacked into. Left false -
            // the default for a bundle - nothing is unpacked and nothing runs.
            useLegacyPackaging = true
            // ...and they are executables, not libraries. The strip AGP would
            // otherwise run over them is at best pointless here.
            keepDebugSymbols += listOf("**/libsharkd.so", "**/libwebshark.so")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

// No dependencies at all: the UI is a WebView and the server is a process.
dependencies { }

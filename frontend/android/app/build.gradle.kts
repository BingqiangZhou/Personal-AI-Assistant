import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.personal_ai_assistant"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlin {
        jvmToolchain(21)
    }

    // Signing configurations
    // 签名配置
    val keystorePropertiesFile = rootProject.file("app/key.properties")
    val useKeystoreSigning = keystorePropertiesFile.exists()

    if (useKeystoreSigning) {
        println("📱 Using keystore signing configuration from key.properties")
    } else {
        println("🔧 Using debug signing configuration (for development)")
    }

    signingConfigs {
        // Create release signing config from key.properties if available
        // 如果 key.properties 可用，从文件创建 release 签名配置
        if (useKeystoreSigning) {
            val keystoreProperties = Properties()
            keystoreProperties.load(keystorePropertiesFile.inputStream())

            create("release") {
                keyAlias = keystoreProperties["keyAlias"] as? String ?: ""
                keyPassword = keystoreProperties["keyPassword"] as? String ?: ""
                storeFile = file(keystoreProperties["storeFile"] as? String ?: "")
                storePassword = keystoreProperties["storePassword"] as? String ?: ""
            }
        }
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.example.personal_ai_assistant"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // Use keystore signing if key.properties exists, otherwise use debug signing
            // 如果 key.properties 存在则使用 keystore 签名，否则使用 debug 签名
            // This allows consistent signature for development builds
            // 这样可以保证开发构建时签名一致
            signingConfig = if (useKeystoreSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }

            // Minify and shrink code
            // 混淆和压缩代码
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }

        debug {
            // Debug builds always use debug signing
            // Debug 构建始终使用 debug 签名
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    // StAX API for XML parsing (required by some plugins)
    // StAX API 用于 XML 解析（某些插件需要）
    implementation("javax.xml.stream:stax-api:1.0-2")
    implementation("com.fasterxml.woodstox:woodstox-core:6.6.2")
}

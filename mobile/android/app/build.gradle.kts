import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// 版本号的唯一来源是仓库根的 version.json，双端与 PC 共用同一个数字。
// 这里手写会立刻和 iOS / 桌面端漂移。
val repoRoot = rootProject.projectDir.parentFile.parentFile
val phantomVersion = groovy.json.JsonSlurper()
    .parseText(File(repoRoot, "version.json").readText()) as Map<*, *>

// 官方信令地址同样只有一个配置源：仓库根的 official.env（纯 KEY=VALUE）。
val officialEnv: Map<String, String> = File(repoRoot, "official.env")
    .takeIf { it.isFile }
    ?.readLines()
    ?.map { it.trim() }
    ?.filter { it.isNotEmpty() && !it.startsWith("#") && it.contains("=") }
    ?.associate { line ->
        val idx = line.indexOf('=')
        line.substring(0, idx).trim() to line.substring(idx + 1).trim()
    }
    ?: emptyMap()

val officialSignalServer = buildString {
    append(officialEnv["OFFICIAL_SIGNAL_SCHEME"] ?: "ws")
    append("://")
    append(officialEnv["OFFICIAL_SIGNAL_HOST"] ?: "qx.coreyuan.cn")
    append(":")
    append(officialEnv["OFFICIAL_SIGNAL_PORT"] ?: "10112")
    append("/ws")
}

android {
    namespace = "com.buildin1.phantom_p2p"
    compileSdk = 36

    defaultConfig {
        // applicationId 沿用旧版本：改了老用户就升不了级，只能重装。
        applicationId = "com.buildin1.phantom_p2p"
        minSdk = 26
        targetSdk = 36
        versionCode = (phantomVersion["buildNumber"] as Number).toInt()
        versionName = phantomVersion["version"] as String

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "OFFICIAL_SIGNAL_SERVER", "\"$officialSignalServer\"")
        // 与 crates/core 的 tun_bridge::TUN_MTU 对齐。改这里必须同时改那里，
        // 否则 QUIC datagram 会超出实测 1162 字节的可用载荷，表现为稳定丢包。
        buildConfigField("int", "TUN_MTU", "1160")
    }

    // ---------------------------------------------------------------------
    // 签名
    //
    // 密钥材料的来源有两处，都不入库：
    //   本地  keystore.properties（见 keystore.properties.example）
    //   CI    环境变量，由 Actions secrets 注入
    //
    // 缺材料时**构建 release 会直接失败**，不产出未签名 APK ——
    // 未签名的包装不上，安静地产出它只会让人下载完才发现白等一场。
    // ---------------------------------------------------------------------
    val keystoreProps = Properties().apply {
        val file = rootProject.file("keystore.properties")
        if (file.isFile) file.inputStream().use { load(it) }
    }

    fun signingValue(key: String, env: String): String? =
        keystoreProps.getProperty(key)?.takeIf { it.isNotBlank() }
            ?: System.getenv(env)?.takeIf { it.isNotBlank() }

    val storeFilePath = signingValue("storeFile", "PHANTOM_KEYSTORE_PATH")
    val resolvedStore = storeFilePath?.let { path ->
        // 绝对路径（CI 注入的）直接用，相对路径按模块目录解析。
        File(path).takeIf { it.isAbsolute } ?: rootProject.file(path)
    }
    val hasSigningMaterial = resolvedStore?.isFile == true

    // 只在真的要构建 release 时才拦。改 UI 的人跑 assembleDebug 不该被签名挡住。
    val buildingRelease = gradle.startParameter.taskNames.any {
        it.contains("Release") || it.contains("bundle", ignoreCase = true)
    }
    if (buildingRelease && !hasSigningMaterial) {
        throw GradleException(
            """
            缺少 release 签名材料，拒绝产出未签名 APK（未签名的包装不上）。

            本地：复制 mobile/android/keystore.properties.example 为 keystore.properties 并填写，
                  keystore 本身放在 mobile/android/ 下（已在 .gitignore 里）。
            CI  ：配置 Actions secrets —— ANDROID_KEYSTORE_BASE64 / ANDROID_KEYSTORE_PASSWORD
                  / ANDROID_KEY_ALIAS / ANDROID_KEY_PASSWORD。

            没有 keystore 就先生成一个：mobile/android/tools/new-keystore.ps1
            """.trimIndent()
        )
    }

    signingConfigs {
        if (hasSigningMaterial) {
            create("release") {
                storeFile = resolvedStore
                storePassword = signingValue("storePassword", "PHANTOM_KEYSTORE_PASSWORD")
                keyAlias = signingValue("keyAlias", "PHANTOM_KEY_ALIAS")
                keyPassword = signingValue("keyPassword", "PHANTOM_KEY_PASSWORD")
                // v1 关掉：minSdk 26 起 v2/v3 就够了，v1 只是拖慢构建。
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            // 只为本地开发保留，CI 不构建它。加后缀是为了能和正式版并存装在同一台机器上。
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    flavorDimensions += "tier"
    productFlavors {
        create("standard") {
            dimension = "tier"
            // 生产版：隐藏开发者选项（信令地址、中继策略、链路细节）
            buildConfigField("boolean", "DEV_TOOLS", "false")
        }
        create("dev") {
            dimension = "tier"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            buildConfigField("boolean", "DEV_TOOLS", "true")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// ---------------------------------------------------------------------------
// Rust 原生库
//
// 目前 crates/mobile 的导出面还没重做（见根目录移动端勘定），所以默认关闭：
// 只改 UI 的人不该被迫装 Rust 工具链。打开方式：
//     ./gradlew assembleDevDebug -Pphantom.buildRustNative=true
// ---------------------------------------------------------------------------
val rustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

val buildRustNative = tasks.register<Exec>("buildRustNative") {
    group = "build"
    description = "用 cargo-ndk 构建 phantom_mobile 动态库"
    workingDir = repoRoot
    commandLine(
        listOf("cargo", "ndk") +
            rustAbis.flatMap { listOf("-t", it) } +
            listOf(
                "-o", "mobile/android/app/src/main/jniLibs",
                "build", "-p", "phantom-mobile", "--release",
            )
    )
}

if (providers.gradleProperty("phantom.buildRustNative").orNull == "true") {
    tasks.named("preBuild") { dependsOn(buildRustNative) }
}

tasks.register<Delete>("cleanRustNative") {
    group = "build"
    delete(file("src/main/jniLibs"))
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.haze)
    implementation(libs.haze.materials)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.zxing.core)
    implementation(libs.camera.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

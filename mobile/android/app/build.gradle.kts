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

    buildTypes {
        debug {
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
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val phantomVersion = groovy.json.JsonSlurper()
    .parseText(rootProject.file("../version.json").readText()) as Map<*, *>

// macOS 外置卷会产生 ._* 资源叉文件，在每次构建前自动清理
tasks.configureEach {
    doFirst {
        projectDir.walkTopDown()
            .filter { it.name.startsWith("._") }
            .forEach { it.delete() }
    }
}

android {
    namespace = "com.buildin1.phantom_p2p"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.buildin1.phantom_p2p"
        minSdk = 26
        targetSdk = 36
        versionCode = (phantomVersion["buildNumber"] as Number).toInt()
        versionName = phantomVersion["version"] as String

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    flavorDimensions += "tier"
    productFlavors {
        create("standard") {
            dimension = "tier"
            // 生产版本：隐藏开发者选项（服务器地址、联机配置细节、中继策略开关）
        }
        create("dev") {
            dimension = "tier"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            // 开发版本：显示全部开发者选项
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true  // 让代码可读取 BuildConfig.FLAVOR
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

val rustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

fun commandExists(command: String): Boolean {
    return ProcessBuilder("sh", "-lc", "command -v $command")
        .redirectErrorStream(true)
        .start()
        .waitFor() == 0
}

fun androidNdkExists(): Boolean {
    val ndkHome = System.getenv("ANDROID_NDK_HOME")
    if (!ndkHome.isNullOrBlank() && file(ndkHome).isDirectory) return true
    val sdkDir = providers.gradleProperty("android.sdk.path").orNull
        ?: System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: rootProject.file("local.properties")
            .takeIf { it.isFile }
            ?.readLines()
            ?.firstOrNull { it.startsWith("sdk.dir=") }
            ?.substringAfter("sdk.dir=")
    return !sdkDir.isNullOrBlank() && file("$sdkDir/ndk").isDirectory && file("$sdkDir/ndk").listFiles()?.any { it.isDirectory } == true
}

fun runChecked(command: List<String>, workingDir: File) {
    val process = ProcessBuilder(command)
        .directory(workingDir)
        .inheritIO()
        .start()
    val exitCode = process.waitFor()
    if (exitCode != 0) {
        throw GradleException("命令执行失败(${exitCode}): ${command.joinToString(" ")}")
    }
}

val buildRustNative = tasks.register("buildRustNative") {
    group = "build"
    description = "Build Rust phantom_mobile shared libraries for Android ABIs using cargo-ndk."
    doLast {
        if (!commandExists("cargo-ndk")) {
            throw GradleException("cargo-ndk 未安装，无法构建 phantom_mobile。请先安装 cargo-ndk 并添加 Android Rust targets。")
        }
        if (!androidNdkExists()) {
            throw GradleException("Android NDK 未安装，无法构建 phantom_mobile。请先通过 Android Studio 安装 NDK，或设置 ANDROID_NDK_HOME。")
        }
        rustAbis.forEach { abi ->
            runChecked(
                listOf("cargo", "ndk", "-t", abi, "-o", "android/app/src/main/jniLibs", "build", "-p", "phantom-mobile", "--release"),
                rootProject.projectDir.parentFile
            )
        }
    }
}

if (providers.gradleProperty("phantom.buildRustNative").orNull == "true") {
    tasks.named("preBuild") {
        dependsOn(buildRustNative)
    }
}

tasks.register("cleanRustNative") {
    group = "build"
    description = "Remove packaged Rust phantom_mobile shared libraries."
    doLast {
        rustAbis.forEach { abi ->
            file("src/main/jniLibs/$abi/libphantom_mobile.so").delete()
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.lifecycle.viewmodel)
    implementation(libs.lifecycle.livedata)
    implementation(libs.fragment.ktx)
    implementation(libs.okhttp)
    implementation(libs.msgpack.jackson)
    implementation(libs.eddsa)
    implementation(libs.recyclerview)
    implementation(libs.coroutines.android)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

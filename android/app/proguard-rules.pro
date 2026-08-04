# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# JNI 回调入口：这些方法只被 native 侧按名字查找，静态分析看不到任何调用点。
# 目前 release 没开 minify，但一旦开启，被裁剪或改名会让回调静默失效——
# 表现是连接流程正常跑但界面收不到任何事件，极难排查。
-keepclasseswithmembernames class com.buildin1.phantom_p2p.NativeSession {
    native <methods>;
    private void onNativeEvent(java.lang.String, java.lang.String);
}
-keepclasseswithmembernames class com.buildin1.phantom_p2p.data.** {
    native <methods>;
}

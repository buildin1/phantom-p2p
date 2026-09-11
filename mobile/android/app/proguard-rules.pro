# JNI 入口点绝不能被混淆或裁掉。
#
# Rust 侧按**全限定名**反查这些符号（导出的是
# Java_com_buildin1_phantom_1p2p_engine_PhantomEngine_nativeXxx），
# 类名、包名、方法名任何一处被改，都是运行时 UnsatisfiedLinkError ——
# 编译期抓不到，只有装到手机上才会炸。
-keep class com.buildin1.phantom_p2p.engine.PhantomEngine { *; }

# Rust 回调进来的三个方法同样按名字查找，必须保名。
-keepclassmembers class com.buildin1.phantom_p2p.engine.PhantomEngine {
    public void onEngineEvent(java.lang.String, java.lang.String);
    public int onEstablishTun(java.lang.String, int, java.lang.String, int);
    public boolean onProtectSocket(int);
}

# VpnService 的这两个方法由 PhantomEngine 直接调用（不经 JNI），
# 但它们是隧道能否建立的关键路径，保住以免被内联优化掉签名。
-keep class com.buildin1.phantom_p2p.vpn.PhantomVpnService {
    public int establishTunnel(java.lang.String, int, java.util.List, int);
    public boolean protectSocket(int);
}

# 引擎的数据类型会被序列化/反射到，整体保留。
-keep class com.buildin1.phantom_p2p.engine.** { *; }

# Compose 自身的规则由 AGP 带入，这里不重复。

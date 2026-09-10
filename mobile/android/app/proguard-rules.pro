# JNI 入口点不能被混淆或裁掉：Rust 侧按全限定名反查这些方法，
# 名字一改就是运行时 NoSuchMethodError，而且只在真机上才会暴露。
-keep class com.buildin1.phantom_p2p.vpn.PhantomVpnService {
    public int establishTunnel(java.lang.String, int, java.util.List);
    public boolean protectSocket(int);
}
-keep class com.buildin1.phantom_p2p.engine.** { *; }

# Compose 自身的规则由 AGP 带入，这里不重复。

package com.buildin1.phantom_p2p

import android.app.Application

class PhantomApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // 日志初始化在 Rust 侧（core 的 logging.rs），日志目录必须是
        // getExternalFilesDir()——写进 filesDir 的话没 root 根本看不到，
        // 而界面按约定隐藏了链路的真实性质，日志是唯一的诊断入口。
        //
        // TODO(FFI)：FFI 落地后在这里调 nativeInitLogging(logDir, dataDir)。
    }

    /** 日志根目录。传给 Rust 侧的 `logging::init`。 */
    fun logDirectory() = (getExternalFilesDir(null) ?: filesDir).resolve("log")

    /** 数据目录：身份密钥、风控自校准数据库。绝不参与云备份。 */
    fun dataDirectory() = filesDir
}

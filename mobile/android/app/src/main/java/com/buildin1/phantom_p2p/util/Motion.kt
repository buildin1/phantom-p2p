package com.buildin1.phantom_p2p.util

import android.provider.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalInspectionMode

/**
 * 系统是否开启了「移除动画 / 减弱动态效果」。
 *
 * 接线台的循环动效、阶段圆点的闪烁都要看这个值。前庭功能障碍的用户在系统里
 * 关掉了动画，应用再自顾自地循环动画就是无视这个设置。
 *
 * 注意：读的是 [Settings.Global.ANIMATOR_DURATION_SCALE] 而不是 TRANSITION_SCALE——
 * 前者管属性动画（我们用的这种），后者只管 Activity 转场。
 */
@Composable
fun rememberReduceMotion(): Boolean {
    // 预览渲染不接系统设置，固定按「不减弱」画，否则 @Preview 里看到的永远是稳态。
    if (LocalInspectionMode.current) return false

    val context = LocalContext.current
    return remember(context) {
        runCatching {
            Settings.Global.getFloat(
                context.contentResolver,
                Settings.Global.ANIMATOR_DURATION_SCALE,
                1f,
            ) == 0f
        }.getOrDefault(false)
    }
}

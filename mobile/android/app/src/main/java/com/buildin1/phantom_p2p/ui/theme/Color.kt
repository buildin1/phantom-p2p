package com.buildin1.phantom_p2p.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * 接线台配色。
 *
 * 这套令牌是设计稿 `mobile/test/android-ui.html` 的唯一代码对应物，iOS 端
 * `DesignSystem/Palette.swift` 逐值相同——双端要认得出是同一个产品。
 *
 * 一条不能破的规矩：**炭橙只表示品牌与「进行中」，永远不表示连接状态**。
 * 状态色只有玉青（已连接）、赭金（警示）、绛（失败）三个。橙色一旦兼职状态色，
 * 「正在连接」和「已连接」就会撞色，接线台构件的三态也就没法只靠颜色区分了。
 */
@Immutable
data class PhantomColors(
    val bg: Color,
    val surface: Color,
    val surface2: Color,
    val surface3: Color,

    val ink: Color,
    val ink2: Color,
    val ink3: Color,

    val line: Color,
    val lineSoft: Color,

    val ember: Color,
    val emberHi: Color,
    val emberWash: Color,
    val onEmber: Color,

    val jade: Color,
    val jadeWash: Color,
    val gold: Color,
    val goldWash: Color,
    val rose: Color,
    val roseWash: Color,

    val isLight: Boolean,
)

val PhantomLightColors = PhantomColors(
    bg = Color(0xFFF2F0EE),
    surface = Color(0xFFFFFFFF),
    surface2 = Color(0xFFE9E6E3),
    surface3 = Color(0xFFDFDBD7),

    ink = Color(0xFF191716),
    ink2 = Color(0xFF6B6560),
    ink3 = Color(0xFF96908A),

    line = Color(0xFFE0DCD7),
    lineSoft = Color(0xFFEBE8E4),

    ember = Color(0xFFC2481A),
    emberHi = Color(0xFFA93C13),
    emberWash = Color(0xFFFBE7DE),
    onEmber = Color(0xFFFFFFFF),

    jade = Color(0xFF12805E),
    jadeWash = Color(0xFFDFF1EA),
    gold = Color(0xFFA8790C),
    goldWash = Color(0xFFF8EFDA),
    rose = Color(0xFFB7304A),
    roseWash = Color(0xFFFAE3E7),

    isLight = true,
)

val PhantomDarkColors = PhantomColors(
    bg = Color(0xFF131211),
    surface = Color(0xFF1C1A19),
    surface2 = Color(0xFF24211F),
    surface3 = Color(0xFF2E2A28),

    ink = Color(0xFFF0ECE8),
    ink2 = Color(0xFFA29A93),
    ink3 = Color(0xFF6E6660),

    line = Color(0xFF2E2A28),
    lineSoft = Color(0xFF231F1E),

    ember = Color(0xFFFF7A45),
    emberHi = Color(0xFFFF9166),
    emberWash = Color(0xFF331E16),
    onEmber = Color(0xFF2A0F05),

    jade = Color(0xFF3FCB9B),
    jadeWash = Color(0xFF10291F),
    gold = Color(0xFFE3B657),
    goldWash = Color(0xFF2C2415),
    rose = Color(0xFFFF8095),
    roseWash = Color(0xFF33191E),

    isLight = false,
)

/**
 * 取色入口。刻意不给默认值兜底——忘记套 [PhantomTheme] 就该在编译后第一帧炸掉，
 * 而不是安静地退回一套谁也没设计过的颜色。
 */
val LocalPhantomColors = staticCompositionLocalOf<PhantomColors> {
    error("PhantomColors 未提供：请把界面包在 PhantomTheme { } 里")
}

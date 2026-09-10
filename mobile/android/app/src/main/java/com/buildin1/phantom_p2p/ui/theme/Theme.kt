package com.buildin1.phantom_p2p.ui.theme

import android.app.Activity
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

/** M3 形状标度，对应稿里的 8 / 12 / 16 / 24 / 28dp。 */
val PhantomShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/**
 * 主题。
 *
 * **刻意不接 Material You 动态取色。** 动态取色会让应用跟着用户壁纸变颜色，
 * 而这个产品的一半意义是「双端看起来是同一个东西」——iOS 没有动态取色，
 * 接了就等于让 Android 单方面漂走。品牌辨识在这里优先于系统个性化。
 *
 * M3 的 ColorScheme 仍然要填，因为 Switch / Snackbar / 涟漪这些系统组件从那里取色；
 * 它由我们自己的令牌派生，而不是反过来。
 */
@Composable
fun PhantomTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) PhantomDarkColors else PhantomLightColors

    val materialScheme = if (darkTheme) {
        darkColorScheme(
            primary = colors.ember,
            onPrimary = colors.onEmber,
            primaryContainer = colors.emberWash,
            onPrimaryContainer = colors.ember,
            secondary = colors.jade,
            onSecondary = colors.bg,
            background = colors.bg,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            surfaceVariant = colors.surface2,
            onSurfaceVariant = colors.ink2,
            outline = colors.ink3,
            outlineVariant = colors.line,
            error = colors.rose,
            onError = colors.bg,
            errorContainer = colors.roseWash,
            onErrorContainer = colors.rose,
        )
    } else {
        lightColorScheme(
            primary = colors.ember,
            onPrimary = colors.onEmber,
            primaryContainer = colors.emberWash,
            onPrimaryContainer = colors.ember,
            secondary = colors.jade,
            onSecondary = colors.surface,
            background = colors.bg,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            surfaceVariant = colors.surface2,
            onSurfaceVariant = colors.ink2,
            outline = colors.ink3,
            outlineVariant = colors.line,
            error = colors.rose,
            onError = colors.surface,
            errorContainer = colors.roseWash,
            onErrorContainer = colors.rose,
        )
    }

    // 状态栏与导航栏图标随主题反色。透明背景在 themes.xml 里已经设过，
    // 这里只管前景，不再重复涂底。
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    CompositionLocalProvider(LocalPhantomColors provides colors) {
        MaterialTheme(
            colorScheme = materialScheme,
            typography = PhantomTypography,
            shapes = PhantomShapes,
            content = content,
        )
    }
}

/** 取色简写：`PhantomTheme.colors.ember`。 */
object PhantomTheme {
    val colors: PhantomColors
        @Composable get() = LocalPhantomColors.current
}

/**
 * 预览包装：给 @Preview 用，省得每个预览都手写一遍主题与底色。
 */
@Composable
fun PhantomPreview(dark: Boolean = false, content: @Composable () -> Unit) {
    PhantomTheme(darkTheme = dark) {
        Box(Modifier.background(LocalPhantomColors.current.bg)) { content() }
    }
}

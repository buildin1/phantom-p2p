package com.buildin1.phantom_p2p.ui.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.unit.dp

/**
 * 图标集。
 *
 * 自己画而不是拉 material-icons-extended：那个包有 1 万多个矢量图，
 * 为了四个导航图标把它整包引进来，APK 会白胖一圈。这里的四个图标与
 * 设计稿和 iOS 端逐笔一致。
 */
object PhantomIcons {

    /** 两节链环——连接。 */
    val Link: ImageVector by lazy {
        strokeIcon("link") {
            moveTo(10f, 13f)
            curveToRelative(1.4f, 1.4f, 3.7f, 1.6f, 5.3f, 0.4f)
            lineToRelative(3f, -3f)
            curveToRelative(1.6f, -1.6f, 1.6f, -4.2f, 0f, -5.8f)
            curveToRelative(-1.6f, -1.6f, -4.2f, -1.6f, -5.8f, 0f)
            lineToRelative(-1.7f, 1.7f)
            moveTo(14f, 11f)
            curveToRelative(-1.4f, -1.4f, -3.7f, -1.6f, -5.3f, -0.4f)
            lineToRelative(-3f, 3f)
            curveToRelative(-1.6f, 1.6f, -1.6f, 4.2f, 0f, 5.8f)
            curveToRelative(1.6f, 1.6f, 4.2f, 1.6f, 5.8f, 0f)
            lineToRelative(1.7f, -1.7f)
        }
    }

    /** 两个人——房间成员。 */
    val Members: ImageVector by lazy {
        strokeIcon("members") {
            moveTo(16f, 19f)
            verticalLineToRelative(-1.5f)
            curveToRelative(0f, -1.9f, -1.6f, -3.5f, -3.5f, -3.5f)
            horizontalLineToRelative(-5f)
            curveTo(5.6f, 14f, 4f, 15.6f, 4f, 17.5f)
            verticalLineTo(19f)
            moveTo(13.5f, 7.5f)
            arcToRelative(3.5f, 3.5f, 0f, true, true, -7f, 0f)
            arcToRelative(3.5f, 3.5f, 0f, true, true, 7f, 0f)
            moveTo(20f, 19f)
            verticalLineToRelative(-1.5f)
            curveToRelative(0f, -1.7f, -1.1f, -3.1f, -2.6f, -3.4f)
            moveTo(15.4f, 4.1f)
            arcToRelative(3.5f, 3.5f, 0f, false, true, 0f, 6.8f)
        }
    }

    /** 心电图折线——诊断。 */
    val Pulse: ImageVector by lazy {
        strokeIcon("pulse") {
            moveTo(3f, 12f)
            horizontalLineToRelative(4f)
            lineToRelative(2.5f, -7f)
            lineToRelative(5f, 14f)
            lineTo(17f, 12f)
            horizontalLineToRelative(4f)
        }
    }

    /** 齿轮——设置。简化成八齿，24dp 下再多就糊了。 */
    val Gear: ImageVector by lazy {
        strokeIcon("gear") {
            moveTo(15f, 12f)
            arcToRelative(3f, 3f, 0f, true, true, -6f, 0f)
            arcToRelative(3f, 3f, 0f, true, true, 6f, 0f)
            moveTo(19.9f, 15f)
            lineToRelative(1.2f, 0.7f)
            lineToRelative(-2f, 3.4f)
            lineToRelative(-1.2f, -0.7f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, -2.4f, 1.4f)
            verticalLineTo(21f)
            horizontalLineToRelative(-3.9f)
            verticalLineToRelative(-1.2f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, -2.4f, -1.4f)
            lineToRelative(-1.2f, 0.7f)
            lineToRelative(-2f, -3.4f)
            lineTo(7.2f, 15f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, 0f, -2.8f)
            lineTo(6f, 11.5f)
            lineToRelative(2f, -3.4f)
            lineToRelative(1.2f, 0.7f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, 2.4f, -1.4f)
            verticalLineTo(6f)
            horizontalLineToRelative(3.9f)
            verticalLineToRelative(1.4f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, 2.4f, 1.4f)
            lineToRelative(1.2f, -0.7f)
            lineToRelative(2f, 3.4f)
            lineToRelative(-1.2f, 0.7f)
            arcToRelative(7.5f, 7.5f, 0f, false, true, 0f, 2.8f)
        }
    }

    /**
     * 统一的描边图标构造：24dp 画布、2dp 圆头圆角描边、跟随 `tint` 取色。
     * 不填充——这套图标的性格来自线条。
     */
    private fun strokeIcon(name: String, path: PathBuilder.() -> Unit): ImageVector =
        ImageVector.Builder(
            name = name,
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).apply {
            addPath(
                pathData = androidx.compose.ui.graphics.vector.PathData(path),
                fill = null,
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 2f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round,
            )
        }.build()
}

package com.buildin1.phantom_p2p.ui.components

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.buildin1.phantom_p2p.util.rememberReduceMotion

/**
 * 不定量进度条。
 *
 * 一段炭橙的光沿着轨道来回扫。用在「知道正在进行、但不知道还要多久」的地方 ——
 * 建房、等待队友、重连。
 *
 * 存在的理由很实际：用户点了「创建房间」之后，如果界面只是静止地显示房间码，
 * 他会以为卡住了或者失败了。**一个持续运动的元素是在说「我还活着」**，
 * 这比任何文案都管用。
 */
@Composable
fun ProgressStrip(
    modifier: Modifier = Modifier,
    color: Color = PhantomTheme.colors.ember,
) {
    val colors = PhantomTheme.colors
    val reduceMotion = rememberReduceMotion()

    val transition = rememberInfiniteTransition(label = "strip")
    val head by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400),
            repeatMode = RepeatMode.Restart,
        ),
        label = "head",
    )

    Canvas(
        modifier
            .fillMaxWidth()
            .height(3.dp)
            .clip(RoundedCornerShape(2.dp)),
    ) {
        drawRect(colors.line)

        if (reduceMotion) {
            // 减弱动态效果时画一条静止的实条：「正在进行」这个事实仍然读得出来。
            drawRect(color.copy(alpha = 0.5f))
            return@Canvas
        }

        // 一段占轨道 40% 的光带，从左扫到右。用渐变让两端柔和，
        // 避免硬边在窄条上显得廉价。
        val bandWidth = size.width * 0.4f
        val start = -bandWidth + (size.width + bandWidth) * head
        drawRect(
            brush = Brush.horizontalGradient(
                colors = listOf(Color.Transparent, color, Color.Transparent),
                startX = start,
                endX = start + bandWidth,
            ),
            topLeft = Offset(start.coerceAtLeast(0f), 0f),
            size = size.copy(
                width = (start + bandWidth).coerceAtMost(size.width) -
                    start.coerceAtLeast(0f),
            ),
        )
    }
}

/**
 * 「正在进行」横幅：一行文字 + 一个转动的小环 + 底下的进度条。
 *
 * 房间页在建房、等待队友时用它占住视觉焦点。
 */
@Composable
fun PreparingBanner(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
) {
    val colors = PhantomTheme.colors
    Column(
        modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Spinner(Modifier.size(16.dp))
            Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = colors.ink,
                )
                if (subtitle != null) {
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.ink2,
                    )
                }
            }
        }
        ProgressStrip()
    }
}

/** 转动的缺口圆环。比 Material 的 CircularProgressIndicator 细，和这套设计的线条一致。 */
@Composable
fun Spinner(
    modifier: Modifier = Modifier,
    color: Color = PhantomTheme.colors.ember,
) {
    val reduceMotion = rememberReduceMotion()
    val transition = rememberInfiniteTransition(label = "spinner")
    val angle by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Restart),
        label = "angle",
    )

    Canvas(modifier.size(16.dp)) {
        val stroke = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
        drawArc(
            color = color.copy(alpha = 0.22f),
            startAngle = 0f,
            sweepAngle = 360f,
            useCenter = false,
            style = stroke,
        )
        drawArc(
            color = color,
            startAngle = if (reduceMotion) -90f else angle - 90f,
            sweepAngle = 90f,
            useCenter = false,
            style = stroke,
        )
    }
}

@Preview(widthDp = 340)
@Composable
private fun PreparingBannerPreview() = PhantomPreview {
    PreparingBanner(
        title = "正在创建房间",
        subtitle = "建好之后把房间码发给队友",
        modifier = Modifier.padding(20.dp),
    )
}

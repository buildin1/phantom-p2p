package com.buildin1.phantom_p2p.ui.components

import androidx.compose.animation.animateColorAsState
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.PunchPhase
import com.buildin1.phantom_p2p.engine.Transport
import com.buildin1.phantom_p2p.engine.displayTitle
import com.buildin1.phantom_p2p.ui.theme.MonoNumber
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.buildin1.phantom_p2p.util.rememberReduceMotion

/**
 * 接线台。
 *
 * 这个产品做的唯一一件事是把两台隔着 NAT 的机器接成一条线，所以界面的主角
 * 就是那条线。三个状态**共用同一个构件**，只换颜色与运动：
 *
 * - 空闲：虚线插口，断开的虚线
 * - 连接中：本机插口点亮成炭橙，一段信号沿线跑
 * - 已接通：两端玉青，实线贯通，插口外扩一圈呼吸光晕
 *
 * 共用构件是刻意的：状态切换时元素原地变色变形，不跳版。三态各画一遍就一定
 * 会在切换瞬间闪一下。
 */
@Composable
fun Patchbay(
    state: ConnectionState,
    modifier: Modifier = Modifier,
    localLabel: String = "本机",
    remoteLabel: String = "对端",
) {
    val colors = PhantomTheme.colors
    val reduceMotion = rememberReduceMotion()

    val isLive = state is ConnectionState.Connected
    val isBusy = state is ConnectionState.Connecting
    val isFailed = state is ConnectionState.Failed

    val localColor by animateColorAsState(
        targetValue = when {
            isLive -> colors.jade
            isBusy -> colors.ember
            isFailed -> colors.rose
            else -> colors.line
        },
        animationSpec = tween(280),
        label = "localJack",
    )
    val remoteColor by animateColorAsState(
        targetValue = if (isLive) colors.jade else colors.line,
        animationSpec = tween(280),
        label = "remoteJack",
    )

    // 0..1 的循环：连接中驱动信号跑动，接通后驱动呼吸光晕。
    // 系统开了「减弱动态效果」时固定在稳态（1f），不再循环。
    val transition = rememberInfiniteTransition(label = "patchbay")
    val animatedPulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(if (isLive) 2600 else 1500),
            repeatMode = RepeatMode.Restart,
        ),
        label = "pulse",
    )
    val pulse = if (reduceMotion) 1f else animatedPulse

    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(74.dp)
                .padding(horizontal = 4.dp),
        ) {
            drawPatchbay(
                localColor = localColor,
                remoteColor = remoteColor,
                idleLineColor = colors.line,
                dashColor = colors.ink3,
                emberStart = colors.ember,
                emberEnd = colors.emberHi,
                jackFill = colors.surface2,
                coreIdle = colors.ink3,
                isLive = isLive,
                isBusy = isBusy && !reduceMotion,
                showStaticRun = isBusy && reduceMotion,
                progress = pulse,
            )
        }

        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(localLabel, style = MonoNumber.copy(fontSize = 10.sp), color = colors.ink3)
            Text(remoteLabel, style = MonoNumber.copy(fontSize = 10.sp), color = colors.ink3)
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(
                text = state.displayTitle,
                style = MaterialTheme.typography.titleLarge.copy(fontSize = 22.sp),
                color = if (isFailed) colors.rose else colors.ink,
                textAlign = TextAlign.Center,
            )
            Text(
                text = state.patchbaySubtitle(),
                style = MaterialTheme.typography.bodyMedium,
                color = colors.ink2,
                textAlign = TextAlign.Center,
            )
        }
    }
}

private fun ConnectionState.patchbaySubtitle(): String = when (this) {
    is ConnectionState.Idle -> "输入房间码，或开一间新的"
    is ConnectionState.Connecting ->
        "已用 %.1fs · 通常 2 秒内完成".format(elapsedMillis / 1000.0)
    is ConnectionState.Connected -> "房间 $roomCode"
    is ConnectionState.Failed -> reason.displayAdvice
}

// ---------------------------------------------------------------------------
// 绘制
// ---------------------------------------------------------------------------

private fun DrawScope.drawPatchbay(
    localColor: Color,
    remoteColor: Color,
    idleLineColor: Color,
    dashColor: Color,
    emberStart: Color,
    emberEnd: Color,
    jackFill: Color,
    coreIdle: Color,
    isLive: Boolean,
    isBusy: Boolean,
    showStaticRun: Boolean,
    progress: Float,
) {
    val jackRadius = 28.dp.toPx()
    val ringStroke = 2.dp.toPx()
    val cableStroke = 3.dp.toPx()
    val coreRadius = 8.dp.toPx()

    val cy = size.height / 2f
    val leftCx = jackRadius
    val rightCx = size.width - jackRadius
    val cableStart = Offset(leftCx + jackRadius, cy)
    val cableEnd = Offset(rightCx - jackRadius, cy)

    if (isLive) {
        drawLine(remoteColor, cableStart, cableEnd, cableStroke, StrokeCap.Round)
    } else {
        drawLine(idleLineColor, cableStart, cableEnd, cableStroke, StrokeCap.Round)
        drawLine(
            color = dashColor.copy(alpha = 0.5f),
            start = cableStart,
            end = cableEnd,
            strokeWidth = cableStroke,
            pathEffect = PathEffect.dashPathEffect(
                floatArrayOf(5.dp.toPx(), 7.dp.toPx()),
                0f,
            ),
        )

        // 信号跑动：前 70% 拉长，后 30% 淡出。减弱动态效果时画成整条静止的实段，
        // 让「正在进行」这个事实仍然读得出来，只是不动。
        if (isBusy || showStaticRun) {
            val head = if (showStaticRun) 1f else (progress / 0.7f).coerceAtMost(1f)
            val alpha = when {
                showStaticRun -> 1f
                progress <= 0.7f -> 1f
                else -> 1f - (progress - 0.7f) / 0.3f
            }
            drawLine(
                brush = Brush.horizontalGradient(
                    colors = listOf(emberStart, emberEnd),
                    startX = cableStart.x,
                    endX = cableEnd.x,
                ),
                start = cableStart,
                end = Offset(cableStart.x + (cableEnd.x - cableStart.x) * head, cy),
                strokeWidth = cableStroke,
                cap = StrokeCap.Round,
                alpha = alpha.coerceIn(0f, 1f),
            )
        }
    }

    drawJack(
        cx = leftCx,
        cy = cy,
        radius = jackRadius,
        ringStroke = ringStroke,
        coreRadius = coreRadius,
        ringColor = localColor,
        coreColor = if (localColor == idleLineColor) coreIdle else localColor,
        fill = jackFill,
        halo = isLive,
        progress = progress,
    )
    drawJack(
        cx = rightCx,
        cy = cy,
        radius = jackRadius,
        ringStroke = ringStroke,
        coreRadius = coreRadius,
        ringColor = remoteColor,
        coreColor = if (isLive) remoteColor else coreIdle,
        fill = jackFill,
        halo = isLive,
        progress = progress,
    )
}

private fun DrawScope.drawJack(
    cx: Float,
    cy: Float,
    radius: Float,
    ringStroke: Float,
    coreRadius: Float,
    ringColor: Color,
    coreColor: Color,
    fill: Color,
    halo: Boolean,
    progress: Float,
) {
    val center = Offset(cx, cy)

    if (halo) {
        // 0.9 倍扩到 1.12 倍，同时淡出
        val scale = 0.9f + 0.22f * progress
        val alpha = (0.35f * (1f - progress / 0.7f)).coerceAtLeast(0f)
        if (alpha > 0f) {
            drawCircle(
                color = ringColor.copy(alpha = alpha),
                radius = (radius + 7.dp.toPx()) * scale,
                center = center,
                style = Stroke(width = 1.5.dp.toPx()),
            )
        }
    }

    drawCircle(fill, radius - ringStroke / 2, center)
    drawCircle(ringColor, radius - ringStroke / 2, center, style = Stroke(width = ringStroke))
    drawCircle(coreColor, coreRadius, center)
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

@Preview(name = "空闲", widthDp = 360)
@Composable
private fun PatchbayIdlePreview() = PhantomPreview {
    Patchbay(ConnectionState.Idle, Modifier.padding(20.dp))
}

@Preview(name = "连接中", widthDp = 360)
@Composable
private fun PatchbayBusyPreview() = PhantomPreview {
    Patchbay(
        state = ConnectionState.Connecting("7K2M9Q", PunchPhase.Punching, 1_800),
        modifier = Modifier.padding(20.dp),
        remoteLabel = "7K2M9Q",
    )
}

@Preview(name = "已接通 · 深色", widthDp = 360)
@Composable
private fun PatchbayLivePreview() = PhantomPreview(dark = true) {
    Patchbay(
        state = ConnectionState.Connected("7K2M9Q", Transport.Udp, "10.66.0.2", "10.66.0.1", 0L),
        modifier = Modifier.padding(20.dp),
        localLabel = "10.66.0.2",
        remoteLabel = "10.66.0.1",
    )
}

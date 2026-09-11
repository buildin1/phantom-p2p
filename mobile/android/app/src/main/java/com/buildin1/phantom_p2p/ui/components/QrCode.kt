package com.buildin1.phantom_p2p.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.InviteToken
import com.buildin1.phantom_p2p.ui.theme.MonoMetric
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * 二维码。
 *
 * ## 为什么自己画，不生成 Bitmap
 *
 * ZXing 给的是 [BitMatrix]（一张布尔表）。常见做法是把它渲染成 Bitmap 再
 * 用 `Image` 显示，但那样在深色模式下要重新生成、缩放时会糊、还要管
 * Bitmap 的生命周期。直接用 Compose 的 [Canvas] 按格子画方块：
 * 分辨率跟随实际尺寸，主题色切换即时生效，也没有可回收对象。
 *
 * ## 纠错等级
 *
 * 用 [ErrorCorrectionLevel.M]（约 15% 冗余）。内容只有 32 个字符，
 * 用 H（30%）会让模块数明显变多、每格变小，在手机屏幕上反而更难扫。
 */
@Composable
fun QrCode(
    content: String,
    modifier: Modifier = Modifier,
) {
    // 编码是纯计算，内容不变就不重算。
    val matrix = remember(content) {
        runCatching {
            QRCodeWriter().encode(
                content,
                BarcodeFormat.QR_CODE,
                // 这两个尺寸只决定 ZXing 内部的输出网格。我们只关心模块的
                // 通断，实际像素尺寸由 Canvas 决定，所以给个够用的值即可。
                QR_RENDER_SIZE,
                QR_RENDER_SIZE,
                mapOf(
                    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                    // 留白交给外层的 padding 统一控制，这里不要 ZXing 再加一圈。
                    EncodeHintType.MARGIN to 0,
                    EncodeHintType.CHARACTER_SET to "UTF-8",
                ),
            )
        }.getOrNull()
    }

    Box(
        modifier = modifier
            .aspectRatio(1f)
            // 二维码必须画在浅底上，深色模式也是。扫码器依赖「暗模块 / 亮背景」
            // 这个对比方向，反色的码很多设备根本不认。
            .clip(RoundedCornerShape(12.dp))
            .background(Color.White)
            .padding(12.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (matrix == null) {
            Text(
                text = "二维码生成失败",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF6B6560),
                textAlign = TextAlign.Center,
            )
            return@Box
        }

        Canvas(Modifier.fillMaxWidth().aspectRatio(1f)) {
            val modules = matrix.width
            if (modules <= 0) return@Canvas
            // 用浮点步长而不是整数像素：整除会在右下角累积出一条空白缝。
            val step = size.minDimension / modules
            for (y in 0 until modules) {
                for (x in 0 until modules) {
                    if (!matrix.get(x, y)) continue
                    drawRect(
                        color = QrForeground,
                        topLeft = Offset(x * step, y * step),
                        // 每格画满一个 step，相邻方块自然拼成连续区块。
                        size = Size(step, step),
                    )
                }
            }
        }
    }
}

/**
 * 邀请卡片：二维码 + 令牌文本 + 刷新入口。
 *
 * [token] 为 null 时显示等待态 —— 令牌是服务端签发的，建房后有一个往返的
 * 空窗期，这段时间要给出「在要了」的反馈，不能是一片空白。
 */
@Composable
fun InviteCard(
    token: InviteToken?,
    onRefresh: () -> Unit,
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PhantomTheme.colors

    PhantomCard(modifier) {
        CardLabel("邀请队友")
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp, bottom = 12.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (token == null) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(0.7f)
                        .aspectRatio(1f)
                        .clip(RoundedCornerShape(12.dp))
                        .background(colors.surface2),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "正在生成邀请…",
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.ink3,
                    )
                }
            } else {
                QrCode(token.uri, Modifier.fillMaxWidth(0.7f))
            }
        }

        Text(
            text = "扫码或点链接即可加入，不用报房间码",
            style = MaterialTheme.typography.bodySmall,
            color = colors.ink3,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )

        if (token != null) {
            Text(
                // 20 位一整行念不下来，按 5 位断开只是为了看，不改变令牌本身。
                text = token.token.chunked(5).joinToString(" "),
                style = MonoMetric.copy(fontWeight = FontWeight.Medium),
                color = colors.ink2,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            InviteAction("复制链接", Modifier.weight(1f), enabled = token != null, onClick = onCopy)
            // 发错群了有救：旧令牌立刻作废，服务端重新签发一个。
            InviteAction("换一个", Modifier.weight(1f), enabled = token != null, onClick = onRefresh)
        }
    }
}

@Composable
private fun InviteAction(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val colors = PhantomTheme.colors
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(colors.surface2)
            .clickable(enabled = enabled, onClick = onClick)
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) colors.ink else colors.ink3,
        )
    }
}

/** ZXing 的内部输出网格尺寸。实际显示尺寸由 Canvas 决定，与它无关。 */
private const val QR_RENDER_SIZE = 512

/** 二维码的暗模块颜色。固定纯黑，不跟随主题 —— 见 [QrCode] 的说明。 */
private val QrForeground = Color(0xFF000000)

@Preview
@Composable
private fun InviteCardPreview() = PhantomPreview {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        InviteCard(
            token = InviteToken(token = "7QFK3M2XJ9WD4NBV6RTZ", roomCode = "AB3K9M"),
            onRefresh = {},
            onCopy = {},
        )
        InviteCard(token = null, onRefresh = {}, onCopy = {})
    }
}

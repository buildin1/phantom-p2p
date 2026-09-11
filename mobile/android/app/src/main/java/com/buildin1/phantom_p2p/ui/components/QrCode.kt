package com.buildin1.phantom_p2p.ui.components

import android.graphics.Bitmap
import androidx.compose.foundation.Image
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
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
    // 编码 + 转位图都是纯计算，内容不变就不重做。
    val bitmap = remember(content) { encodeQrBitmap(content) }

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
        if (bitmap == null) {
            Text(
                text = "二维码生成失败",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF6B6560),
                textAlign = TextAlign.Center,
            )
            return@Box
        }

        Image(
            bitmap = bitmap,
            contentDescription = "邀请二维码",
            modifier = Modifier.fillMaxWidth().aspectRatio(1f),
            // 位图只有模块那么大（约 41×41 像素），放大到屏幕尺寸靠这里。
            // FilterQuality.None = 最近邻，方块边缘保持锐利；
            // 用默认的双线性会把边缘糊掉，扫码器就不容易认了。
            filterQuality = FilterQuality.None,
        )
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
    error: String?,
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
                        // 等不到令牌最常见的原因是信令服务端还没更新 ——
                        // 一直转「正在生成」和卡死没区别，必须说清楚并给出路。
                        text = error ?: "正在生成邀请…",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (error != null) colors.ink2 else colors.ink3,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 16.dp),
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

/**
 * 把内容编码成**模块分辨率**的位图（约 41×41 像素），失败返回 null。
 *
 * ## 这里踩过一个很贵的坑
 *
 * `QRCodeWriter.encode(content, QR_CODE, 512, 512, hints)` 返回的 BitMatrix
 * 是 **512×512**，不是模块网格 —— ZXing 会把码放大到你要求的尺寸。
 * 之前这里按 `matrix.width` 逐格 `drawRect`，等于**每帧 26 万次绘制调用**，
 * 而且它还在一个滚动容器里：展开二维码后整个页面几乎滑不动。
 *
 * 现在传 `0, 0`，拿到的就是自然的模块网格（`outputWidth = max(0, inputWidth)`，
 * 缩放倍数为 1）；一次性转成位图，之后每帧只有一次绘制。
 */
private fun encodeQrBitmap(content: String): ImageBitmap? = runCatching {
    val matrix = QRCodeWriter().encode(
        content,
        BarcodeFormat.QR_CODE,
        // 0 = 不放大，直接给模块网格。放大交给显示层做。
        0,
        0,
        mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            // 留白交给外层的白底 padding，不要 ZXing 再加一圈。
            EncodeHintType.MARGIN to 0,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        ),
    )

    val width = matrix.width
    val height = matrix.height
    val pixels = IntArray(width * height)
    for (y in 0 until height) {
        val row = y * width
        for (x in 0 until width) {
            pixels[row + x] = if (matrix.get(x, y)) QR_DARK else QR_LIGHT
        }
    }
    Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888).asImageBitmap()
}.getOrNull()

/** 二维码的暗/亮模块颜色。固定黑白，不跟随主题 —— 见 [QrCode] 的说明。 */
private const val QR_DARK = 0xFF000000.toInt()
private const val QR_LIGHT = 0xFFFFFFFF.toInt()

@Preview
@Composable
private fun InviteCardPreview() = PhantomPreview {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        InviteCard(
            token = InviteToken(token = "7QFK3M2XJ9WD4NBV6RTZ", roomCode = "AB3K9M"),
            error = null,
            onRefresh = {},
            onCopy = {},
        )
        InviteCard(token = null, error = null, onRefresh = {}, onCopy = {})
        InviteCard(
            token = null,
            error = "服务器暂不支持二维码邀请，请用房间码",
            onRefresh = {},
            onCopy = {},
        )
    }
}

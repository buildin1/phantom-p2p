package com.buildin1.phantom_p2p.ui.components

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview as CameraPreview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
// lifecycle 2.8 起 LocalLifecycleOwner 搬到了这里，compose.ui 里的那个已弃用。
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.buildin1.phantom_p2p.engine.InviteToken
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 扫码取景框。
 *
 * ## 为什么是 ZXing 而不是 ML Kit
 *
 * ML Kit 的条码识别要么依赖 Google Play 服务（国内大量设备没有，扫码会直接
 * 不可用），要么捆绑约 3MB 的模型。ZXing core 是纯 Java、约 500KB、零服务依赖，
 * 在这个应用的用户群里是唯一能保证一定能用的那个。
 *
 * 代价是解码要自己接：CameraX 只负责取景与逐帧回调，YUV 平面转成
 * [PlanarYUVLuminanceSource] 交给 [MultiFormatReader]。
 *
 * ## 只解码 Y 平面
 *
 * `ImageProxy` 的 format 是 YUV_420_888，三个平面。二维码只需要亮度，
 * 也就是 Y 平面，色度平面直接不读 —— 省掉一次全帧色彩转换，在中低端机上
 * 是能否跟上帧率的分水岭。
 *
 * @param onToken 扫到有效邀请令牌时回调。**只会触发一次** —— 扫到之后立刻
 *                停止分析，否则同一张码会在几十毫秒内连续命中十几次。
 */
@Composable
fun QrScanner(
    onToken: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val colors = PhantomTheme.colors

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var denied by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasPermission = granted
        denied = !granted
    }

    LaunchedEffect(Unit) {
        if (!hasPermission) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .clip(RoundedCornerShape(16.dp))
            .background(colors.surface2),
        contentAlignment = Alignment.Center,
    ) {
        when {
            hasPermission -> {
                CameraPreviewSurface(onToken = onToken, modifier = Modifier.fillMaxSize())
                // 取景提示框。不做遮罩裁切：CameraX 分析的是整帧，
                // 画一个只框住中间的遮罩会让用户以为框外扫不到。
                Box(
                    modifier = Modifier
                        .fillMaxWidth(0.66f)
                        .aspectRatio(1f)
                        .border(2.dp, colors.ember, RoundedCornerShape(12.dp))
                )
            }

            denied -> ScannerNotice(
                title = "需要相机权限",
                detail = "扫码要用相机。可在系统设置里为本应用打开相机权限，或改用手动输入房间码。",
                actionText = "再试一次",
                onAction = { permissionLauncher.launch(Manifest.permission.CAMERA) },
            )

            else -> ScannerNotice(title = "正在请求相机权限…", detail = "")
        }
    }
}

@Composable
private fun CameraPreviewSurface(
    onToken: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    // 回调可能在重组间变化，但分析器只绑定一次 —— 用 rememberUpdatedState
    // 让分析器始终看到最新的那个，而不是捕获到第一次的旧引用。
    val currentOnToken by rememberUpdatedState(onToken)

    // 单线程就够：解码是 CPU 密集的，多线程只会互相抢核并让帧序错乱。
    val executor = remember { Executors.newSingleThreadExecutor() }
    // 扫到之后就不再解码。没有这个闸门，一张码会在几十毫秒内命中十几次，
    // 于是加入房间被触发十几遍。
    val consumed = remember { AtomicBoolean(false) }

    val reader = remember {
        MultiFormatReader().apply {
            setHints(
                mapOf(
                    // 只认二维码。不限制格式的话会把条码、Data Matrix 都试一遍，
                    // 每帧的解码耗时成倍上涨。
                    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                )
            )
        }
    }

    DisposableEffect(Unit) {
        onDispose { executor.shutdown() }
    }

    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            val previewView = PreviewView(ctx).apply {
                scaleType = PreviewView.ScaleType.FILL_CENTER
            }
            val providerFuture = ProcessCameraProvider.getInstance(ctx)
            providerFuture.addListener({
                val provider = runCatching { providerFuture.get() }.getOrNull()
                    ?: return@addListener

                val preview = CameraPreview.Builder().build().apply {
                    setSurfaceProvider(previewView.surfaceProvider)
                }

                val analysis = ImageAnalysis.Builder()
                    // 解码跟不上就丢帧，不要排队 —— 排队会让取景明显滞后，
                    // 用户以为卡住了，其实只是在处理几秒前的画面。
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                analysis.setAnalyzer(executor) { image ->
                    if (consumed.get()) {
                        image.close()
                        return@setAnalyzer
                    }
                    val token = decodeQr(image, reader)
                    image.close()
                    if (token != null && consumed.compareAndSet(false, true)) {
                        previewView.post { currentOnToken(token) }
                    }
                }

                runCatching {
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                }.onFailure { Log.e(TAG, "相机绑定失败", it) }
            }, ContextCompat.getMainExecutor(ctx))

            previewView
        },
    )
}

/**
 * 从一帧里解出邀请令牌；这一帧没有有效二维码时返回 null。
 *
 * 返回的是**令牌本身**，不是二维码原文 —— 别人的二维码（网址、名片）也会被
 * 解出来，但 [InviteToken.parse] 会把它们挡掉，所以扫到无关的码不会有反应。
 */
private fun decodeQr(image: ImageProxy, reader: MultiFormatReader): String? {
    val plane = image.planes.firstOrNull() ?: return null
    val buffer = plane.buffer
    val bytes = ByteArray(buffer.remaining())
    buffer.get(bytes)
    // buffer 的读位置被上面消费掉了。ImageProxy 可能被复用，
    // 不还原的话下一帧会从中间开始读，解出来全是噪声。
    buffer.rewind()

    // rowStride 常常大于 width（每行有对齐填充），所以源要按 rowStride 建、
    // 再按 width 裁剪。dataHeight 不能直接用 image.height：最后一行未必补满
    // 填充字节，按 rowStride 乘出来会超过实际长度，ZXing 取像素时越界。
    val rowStride = plane.rowStride
    if (rowStride <= 0) return null
    val dataHeight = minOf(image.height, bytes.size / rowStride)
    if (dataHeight <= 0 || image.width > rowStride) return null

    val source = PlanarYUVLuminanceSource(
        bytes,
        rowStride,
        dataHeight,
        0,
        0,
        image.width,
        dataHeight,
        false,
    )

    val bitmap = BinaryBitmap(HybridBinarizer(source))
    val raw = runCatching { reader.decodeWithState(bitmap) }.getOrNull()?.text
    // 每帧都要复位，否则上一帧的中间状态会影响这一帧的判定。
    reader.reset()

    return raw?.let { InviteToken.parse(it) }
}

@Composable
private fun ScannerNotice(
    title: String,
    detail: String,
    actionText: String? = null,
    onAction: (() -> Unit)? = null,
) {
    val colors = PhantomTheme.colors
    Column(
        modifier = Modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = colors.ink,
            textAlign = TextAlign.Center,
        )
        if (detail.isNotEmpty()) {
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = colors.ink3,
                textAlign = TextAlign.Center,
            )
        }
        if (actionText != null && onAction != null) {
            Text(
                text = actionText,
                style = MaterialTheme.typography.labelLarge,
                color = colors.ember,
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .clickable(onClick = onAction)
                    .padding(horizontal = 12.dp, vertical = 6.dp),
            )
        }
    }
}

private const val TAG = "QrScanner"

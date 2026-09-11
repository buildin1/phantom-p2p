package com.buildin1.phantom_p2p.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.buildin1.phantom_p2p.ui.theme.MonoNumber
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.buildin1.phantom_p2p.update.AppUpdateInfo
import com.buildin1.phantom_p2p.update.UpdateState

/**
 * 版本更新弹层。
 *
 * ## 强制与非强制的区别只有一处
 *
 * 强制更新（当前版本低于服务端声明的 `min_supported`）**不给「以后再说」**，
 * 也不能点外面关掉。非强制的可以随时忽略。除此之外两者完全一样 ——
 * 不用不同的措辞吓唬人。
 *
 * ## 下载中不让关
 *
 * 下载过程里关掉弹层，用户就再也看不到进度，也不知道什么时候能装。
 * 所以一旦开始下载，关闭入口一律消失，直到成功或失败。
 */
@Composable
fun UpdateDialog(
    info: AppUpdateInfo,
    state: UpdateState,
    /** 系统是否已允许本应用安装 APK。false 时主按钮改为「去授权」。 */
    canInstall: Boolean,
    onUpdate: () -> Unit,
    onGrantInstallPermission: () -> Unit,
    onDismiss: () -> Unit,
) {
    val colors = PhantomTheme.colors
    val busy = state is UpdateState.Downloading ||
        state is UpdateState.Verifying ||
        state is UpdateState.Installing
    val dismissible = !info.mandatory && !busy

    Dialog(
        onDismissRequest = { if (dismissible) onDismiss() },
        properties = DialogProperties(
            dismissOnBackPress = dismissible,
            dismissOnClickOutside = dismissible,
        ),
    ) {
        Surface(shape = RoundedCornerShape(20.dp), color = colors.surface) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = if (info.mandatory) "当前版本已失效" else "有新版本可用",
                    style = MaterialTheme.typography.titleMedium,
                    color = colors.ink,
                )
                Text(
                    text = if (info.mandatory) {
                        "请及时更新，旧版本已无法继续使用。"
                    } else {
                        "最新版本 ${info.latestVersion}"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.ink2,
                )

                if (info.notes.isNotEmpty()) {
                    Text(
                        text = info.notes,
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.ink3,
                    )
                }

                when (state) {
                    is UpdateState.Downloading -> DownloadProgress(state)

                    UpdateState.Verifying -> StatusLine("正在校验安装包…", colors.ink2)

                    UpdateState.Installing -> StatusLine("正在唤起系统安装…", colors.ink2)

                    is UpdateState.Failed -> StatusLine(state.reason, colors.rose)

                    UpdateState.Idle -> if (!canInstall) {
                        StatusLine(
                            // 这一步绕不过去，提前说清楚比让用户撞上系统弹窗好。
                            "Android 需要你先在系统设置里允许本应用安装应用。",
                            colors.ink3,
                        )
                    }
                }

                Row(
                    Modifier.fillMaxWidth().padding(top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (dismissible) {
                        TextButton(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                            Text("以后再说", color = colors.ink2)
                        }
                    }
                    Button(
                        onClick = if (canInstall) onUpdate else onGrantInstallPermission,
                        enabled = !busy,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.ember,
                            contentColor = colors.onEmber,
                        ),
                    ) {
                        Text(
                            text = when {
                                busy -> "进行中…"
                                !canInstall -> "去授权"
                                state is UpdateState.Failed -> "重试"
                                else -> "立即更新"
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DownloadProgress(state: UpdateState.Downloading) {
    val colors = PhantomTheme.colors
    val animated by animateFloatAsState(
        targetValue = state.percent / 100f,
        animationSpec = tween(200),
        label = "update-progress",
    )

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(colors.surface2)
        ) {
            Box(
                Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(animated.coerceIn(0f, 1f))
                    .clip(RoundedCornerShape(3.dp))
                    .background(colors.ember)
            )
        }
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("正在下载", style = MaterialTheme.typography.bodySmall, color = colors.ink2)
            Text(
                // 总大小未知时（服务器没给 Content-Length）只报已下载量，
                // 不要编一个假的百分比。
                text = if (state.total > 0) {
                    "${state.percent}% · ${formatMb(state.bytes)} / ${formatMb(state.total)}"
                } else {
                    formatMb(state.bytes)
                },
                style = MonoNumber,
                color = colors.ink3,
            )
        }
    }
}

@Composable
private fun StatusLine(text: String, color: androidx.compose.ui.graphics.Color) {
    Text(text = text, style = MaterialTheme.typography.bodySmall, color = color)
}

private fun formatMb(bytes: Long): String = "%.1f MB".format(bytes / 1024.0 / 1024.0)

@Preview
@Composable
private fun UpdateDialogPreview() = PhantomPreview {
    UpdateDialog(
        info = AppUpdateInfo(
            platform = "android",
            latestVersion = "3.3.0",
            minSupported = "3.2.0",
            downloadUrl = "",
            sha256 = "a".repeat(64),
            notes = "修复房间码删不掉、加入房间后再建房卡死；诊断页重做。",
            mandatory = false,
        ),
        state = UpdateState.Downloading(42, 4_200_000, 10_000_000),
        canInstall = true,
        onUpdate = {}, onGrantInstallPermission = {}, onDismiss = {},
    )
}

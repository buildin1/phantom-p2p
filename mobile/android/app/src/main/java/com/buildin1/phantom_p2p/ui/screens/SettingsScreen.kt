package com.buildin1.phantom_p2p.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.ui.components.GroupLabel
import com.buildin1.phantom_p2p.ui.components.PhantomCard
import com.buildin1.phantom_p2p.ui.components.PillTone
import com.buildin1.phantom_p2p.ui.components.RowDivider
import com.buildin1.phantom_p2p.ui.components.RowValue
import com.buildin1.phantom_p2p.ui.components.SettingRow
import com.buildin1.phantom_p2p.ui.components.StatusPill
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

/** 设置页承载的全部偏好。与引擎无关，存在本机。 */
data class SettingsUiState(
    val nickname: String,
    val deviceId: String,
    val rememberRoomCode: Boolean,
    val autoConnectOnLaunch: Boolean,
    val notificationActions: Boolean,
    val alwaysOnVpnEnabled: Boolean,
    val batteryOptimizationIgnored: Boolean,
    val versionName: String,
    val versionCode: Int,
    val devTools: Boolean,
)

@Composable
fun SettingsScreen(
    state: SettingsUiState,
    onEditNickname: () -> Unit,
    onToggleRememberRoom: (Boolean) -> Unit,
    onToggleAutoConnect: (Boolean) -> Unit,
    onToggleNotificationActions: (Boolean) -> Unit,
    onOpenAlwaysOnSettings: () -> Unit,
    onRequestIgnoreBatteryOptimization: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Spacer(Modifier.height(contentPadding.calculateTopPadding()))
        GroupLabel("身份")
        PhantomCard {
            SettingRow(
                title = "昵称",
                subtitle = "队友在成员列表里看到的名字",
                onClick = onEditNickname,
                trailing = { RowValue(state.nickname) },
            )
            RowDivider()
            SettingRow(
                title = "设备 ID",
                subtitle = "由本机密钥生成，换设备会变",
                trailing = { RowValue(state.deviceId, mono = true) },
            )
        }

        GroupLabel("连接")
        PhantomCard {
            SettingRow(
                title = "记住房间码",
                subtitle = "在连接页显示最近用过的房间",
                trailing = { PhantomSwitch(state.rememberRoomCode, onToggleRememberRoom) },
            )
            RowDivider()
            SettingRow(
                title = "启动后自动连接",
                subtitle = "打开应用即接上次的房间",
                trailing = { PhantomSwitch(state.autoConnectOnLaunch, onToggleAutoConnect) },
            )
            RowDivider()
            SettingRow(
                title = "通知栏快捷操作",
                subtitle = "不进应用也能断开或重连",
                trailing = {
                    PhantomSwitch(state.notificationActions, onToggleNotificationActions)
                },
            )
        }

        // 这一组是 Android 独有的：iOS 用「按需连接」解决同一个问题，形态完全不同。
        //
        // 两项都用状态药丸而不是开关——它们都要跳系统设置才能改，
        // 做成开关会骗用户以为应用能自己改。
        GroupLabel("后台存活 · Android 特有")
        PhantomCard {
            SettingRow(
                title = "始终开启 VPN",
                subtitle = "系统设置里打开后，进程被杀会自动重启",
                onClick = onOpenAlwaysOnSettings,
                trailing = {
                    StatusPill(
                        text = if (state.alwaysOnVpnEnabled) "已开启" else "未开启",
                        tone = if (state.alwaysOnVpnEnabled) PillTone.Ok else PillTone.Warn,
                    )
                },
            )
            RowDivider()
            SettingRow(
                title = "忽略电池优化",
                subtitle = "避免息屏后被系统冻结",
                onClick = onRequestIgnoreBatteryOptimization,
                trailing = {
                    StatusPill(
                        text = if (state.batteryOptimizationIgnored) "已允许" else "未允许",
                        tone = if (state.batteryOptimizationIgnored) PillTone.Ok else PillTone.Warn,
                    )
                },
            )
        }

        GroupLabel("关于")
        PhantomCard {
            SettingRow(
                title = "版本",
                trailing = {
                    RowValue("${state.versionName} (${state.versionCode})", mono = true)
                },
            )
            if (state.devTools) {
                RowDivider()
                SettingRow(
                    title = "开发者选项",
                    subtitle = "信令地址、中继策略、链路细节",
                    trailing = { RowValue("dev 版可见") },
                )
            }
        }

        Spacer(Modifier.height(contentPadding.calculateBottomPadding() + 8.dp))
    }
}

@Composable
private fun PhantomSwitch(checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    val colors = PhantomTheme.colors
    Switch(
        checked = checked,
        onCheckedChange = onCheckedChange,
        colors = SwitchDefaults.colors(
            checkedThumbColor = colors.onEmber,
            checkedTrackColor = colors.ember,
            checkedBorderColor = colors.ember,
            uncheckedThumbColor = colors.ink3,
            uncheckedTrackColor = colors.surface3,
            uncheckedBorderColor = colors.ink3,
        ),
    )
}

private val previewState = SettingsUiState(
    nickname = "阿祈",
    deviceId = "a4f2c918",
    rememberRoomCode = true,
    autoConnectOnLaunch = false,
    notificationActions = true,
    alwaysOnVpnEnabled = false,
    batteryOptimizationIgnored = true,
    versionName = "3.2.2",
    versionCode = 387,
    devTools = false,
)

@Preview(widthDp = 384, heightDp = 760)
@Composable
private fun SettingsPreview() = PhantomPreview {
    SettingsScreen(previewState, {}, {}, {}, {}, {}, {})
}

@Preview(name = "深色", widthDp = 384, heightDp = 760)
@Composable
private fun SettingsDarkPreview() = PhantomPreview(dark = true) {
    SettingsScreen(previewState, {}, {}, {}, {}, {}, {})
}

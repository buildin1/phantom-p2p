package com.buildin1.phantom_p2p

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.FakeEngineClient
import com.buildin1.phantom_p2p.ui.RootScreen
import com.buildin1.phantom_p2p.vpn.PhantomVpnService
import com.buildin1.phantom_p2p.ui.Tab
import com.buildin1.phantom_p2p.ui.screens.ConnectScreen
import com.buildin1.phantom_p2p.ui.screens.DiagnosticsScreen
import com.buildin1.phantom_p2p.ui.screens.RoomScreen
import com.buildin1.phantom_p2p.ui.screens.SettingsScreen
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import kotlinx.coroutines.MainScope

class MainActivity : ComponentActivity() {

    /** 等 VPN 授权回来后要执行的动作（加入房间 / 建房）。 */
    private var pendingAction: (() -> Unit)? = null

    private val viewModel: PhantomViewModel by viewModels {
        viewModelFactory {
            initializer {
                PhantomViewModel(
                    // TODO(FFI)：换成真引擎。接口不变，只换这一行。
                    engine = FakeEngineClient(MainScope()),
                    prefs = PhantomPreferences(applicationContext),
                )
            }
        }
    }

    /**
     * VPN 授权。系统弹窗由 [VpnService.prepare] 触发，用户点「确定」后
     * 才能建虚拟网卡。拒绝了就把状态退回未连接，并在界面上说清楚原因。
     */
    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startTunnelService()
        } else {
            viewModel.cancel()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            PhantomTheme {
                val tab by viewModel.tab.collectAsStateWithLifecycle()
                val state by viewModel.connectionState.collectAsStateWithLifecycle()
                val stats by viewModel.linkStats.collectAsStateWithLifecycle()
                val members by viewModel.members.collectAsStateWithLifecycle()
                val profile by viewModel.networkProfile.collectAsStateWithLifecycle()
                val draft by viewModel.draftCode.collectAsStateWithLifecycle()
                val recents by viewModel.recentRooms.collectAsStateWithLifecycle()
                val settings by viewModel.settings.collectAsStateWithLifecycle()
                val toast by viewModel.toast.collectAsStateWithLifecycle()

                val snackbarHost = remember { SnackbarHostState() }
                LaunchedEffect(toast) {
                    toast?.let {
                        snackbarHost.showSnackbar(it)
                        viewModel.consumeToast()
                    }
                }

                RootScreen(
                    selectedTab = tab,
                    onSelectTab = viewModel::selectTab,
                    connectionState = state,
                    onOpenAppSettings = { viewModel.selectTab(Tab.Settings) },
                ) { current ->
                    when (current) {
                        Tab.Connect -> ConnectScreen(
                            state = state,
                            stats = stats,
                            members = members,
                            draftCode = draft,
                            recentRooms = recents,
                            onDraftClick = { /* 交给系统输入法，见下方 TODO */ },
                            onJoin = { requestVpnThen { viewModel.join() } },
                            onCreateRoom = { requestVpnThen { viewModel.createRoom() } },
                            onPickRecent = { code ->
                                viewModel.setDraftCode(code)
                                requestVpnThen { viewModel.join(code) }
                            },
                            onCancel = viewModel::cancel,
                            onDisconnect = viewModel::disconnect,
                            onRetry = viewModel::retry,
                        )

                        Tab.Room -> {
                            val connected = state as? ConnectionState.Connected
                            RoomScreen(
                                roomCode = connected?.roomCode,
                                subnet = "10.66.0.0/24",
                                mtu = BuildConfig.TUN_MTU,
                                members = members,
                                isHost = members.firstOrNull { it.isSelf }?.isHost == true,
                                onCopyCode = viewModel::copyRoomCode,
                                onShowQr = { /* TODO: 二维码弹层 */ },
                                onLeave = viewModel::disconnect,
                            )
                        }

                        Tab.Diagnostics -> DiagnosticsScreen(
                            stats = stats,
                            profile = profile,
                            logSizeText = "尚未产生日志",
                            onReprobe = viewModel::reprobe,
                            onOpenLogs = { /* TODO: 日志列表页 */ },
                            onReportProblem = viewModel::reportProblem,
                        )

                        Tab.Settings -> SettingsScreen(
                            state = settings,
                            onEditNickname = { /* TODO: 昵称编辑弹层 */ },
                            onToggleRememberRoom = viewModel::setRememberRoomCode,
                            onToggleAutoConnect = viewModel::setAutoConnect,
                            onToggleNotificationActions = viewModel::setNotificationActions,
                            onOpenAlwaysOnSettings = ::openVpnSystemSettings,
                            onRequestIgnoreBatteryOptimization = ::requestIgnoreBatteryOptimization,
                        )
                    }
                }

                SnackbarHost(snackbarHost)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // 用户可能刚从系统设置回来，把 always-on / 电池优化这两个开关的实际状态重新读一遍。
        viewModel.refreshSystemToggles()
    }

    /**
     * 建虚拟网卡前必须先拿到 VPN 授权。已授权时 [VpnService.prepare] 返回 null，
     * 直接往下走；否则弹系统对话框，授权回调里再执行挂起的动作。
     */
    private fun requestVpnThen(action: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            startTunnelService()
            action()
        } else {
            pendingAction = action
            vpnPermission.launch(intent)
        }
    }

    private fun startTunnelService() {
        startForegroundService(Intent(this, PhantomVpnService::class.java))
        pendingAction?.invoke()
        pendingAction = null
    }

    private fun openVpnSystemSettings() {
        runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
    }

    private fun requestIgnoreBatteryOptimization() {
        runCatching {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }
}

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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.buildin1.phantom_p2p.engine.InviteToken
import com.buildin1.phantom_p2p.engine.JniEngineClient
import com.buildin1.phantom_p2p.ui.RootScreen
import com.buildin1.phantom_p2p.ui.components.QrScanner
import com.buildin1.phantom_p2p.ui.components.UpdateDialog
import com.buildin1.phantom_p2p.update.AppUpdater
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

    /**
     * 每次 onResume 推进一格。
     *
     * 用来让那些「只能从系统读、系统又不会通知我们」的开关重新求值 ——
     * 目前是「允许安装未知应用」。用户去系统设置授权后回到应用，
     * 没有这个信号，界面会一直停在「去授权」。
     */
    private var resumeTick by mutableIntStateOf(0)

    private val viewModel: PhantomViewModel by viewModels {
        viewModelFactory {
            initializer {
                val app = applicationContext as PhantomApp
                PhantomViewModel(
                    engine = JniEngineClient(
                        scope = MainScope(),
                        signalUrl = BuildConfig.OFFICIAL_SIGNAL_SERVER,
                        logDir = app.logDirectory().absolutePath,
                        dataDir = app.dataDirectory().absolutePath,
                        devMode = BuildConfig.DEV_TOOLS,
                    ),
                    prefs = PhantomPreferences(applicationContext),
                    updater = AppUpdater(applicationContext),
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
            runPendingAction()
        } else {
            // 拒绝了就必须把挂起的动作丢掉，不然它会在下一次授权流程里被误触发。
            pendingAction = null
            viewModel.cancel()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // 冷启动被链接拉起的那一次。热启动走 onNewIntent。
        handleDeepLink(intent)

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
                val invite by viewModel.inviteToken.collectAsStateWithLifecycle()
                val inviteErr by viewModel.inviteError.collectAsStateWithLifecycle()
                val diagnostics by viewModel.diagnostics.collectAsStateWithLifecycle()
                val diagProgress by viewModel.diagnosticsProgress.collectAsStateWithLifecycle()
                val diagError by viewModel.diagnosticsError.collectAsStateWithLifecycle()
                val pendingUpdate by viewModel.pendingUpdate.collectAsStateWithLifecycle()
                val updateState by viewModel.updateState.collectAsStateWithLifecycle()

                // 扫码是一层覆盖，不是第五个标签页：它是「加入房间」的一条
                // 输入路径，扫完就该回到原来的位置，不该在底栏留下痕迹。
                var showScanner by rememberSaveable { mutableStateOf(false) }

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
                ) { current, insets ->
                    // insets 是顶栏与底栏（含系统留白）占掉的高度。各页面把它
                    // 加在滚动容器**内部** —— 加在外面会把内容裁在两条栏杆之间，
                    // 毛玻璃后面就没东西可模糊了。

                    when (current) {
                        Tab.Connect -> ConnectScreen(
                            contentPadding = insets,
                            state = state,
                            stats = stats,
                            members = members,
                            draftCode = draft,
                            recentRooms = recents,
                            onDraftChange = viewModel::setDraftCode,
                            onJoin = { requestVpnThen { viewModel.join() } },
                            onCreateRoom = { requestVpnThen { viewModel.createRoom() } },
                            onPickRecent = { code ->
                                viewModel.setDraftCode(code)
                                requestVpnThen { viewModel.join(code) }
                            },
                            onScan = { showScanner = true },
                            onCancel = viewModel::cancel,
                            onDisconnect = viewModel::disconnect,
                            onRetry = viewModel::retry,
                        )

                        Tab.Room -> RoomScreen(
                            contentPadding = insets,
                            // 传整个 state，不是只传 Connected 时的房间码：
                            // 建房后隧道还没建好那一两秒，房间码已经有了，
                            // 必须显示出来并配上进行中动效，否则用户以为创建失败了。
                            state = state,
                            subnet = "10.66.0.0/24",
                            mtu = BuildConfig.TUN_MTU,
                            members = members,
                            isHost = members.firstOrNull { it.isSelf }?.isHost == true,
                            inviteToken = invite,
                            inviteError = inviteErr,
                            onCopyCode = viewModel::copyRoomCode,
                            onShowQr = viewModel::requestInvite,
                            onCopyInvite = viewModel::copyInviteLink,
                            onRefreshInvite = viewModel::refreshInvite,
                            onLeave = viewModel::disconnect,
                        )

                        Tab.Diagnostics -> DiagnosticsScreen(
                            contentPadding = insets,
                            stats = stats,
                            profile = profile,
                            diagnostics = diagnostics,
                            progress = diagProgress,
                            error = diagError,
                            logSizeText = "尚未产生日志",
                            onReprobe = viewModel::reprobe,
                            onOpenLogs = { /* TODO: 日志列表页 */ },
                            onReportProblem = viewModel::reportProblem,
                        )

                        Tab.Settings -> SettingsScreen(
                            contentPadding = insets,
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

                pendingUpdate?.let { info ->
                    UpdateDialog(
                        info = info,
                        state = updateState,
                        // 「允许安装未知应用」是系统设置里的开关，改动不会通知应用。
                        // 挂在 resumeTick 上重算：用户从系统设置页回来时 onResume
                        // 会推进它，按钮才会从「去授权」变成「立即更新」。
                        canInstall = remember(resumeTick) { viewModel.canInstallUpdate() },
                        onUpdate = viewModel::startUpdate,
                        onGrantInstallPermission = {
                            viewModel.unknownSourcesIntent()?.let { intent ->
                                runCatching { startActivity(intent) }
                            }
                        },
                        onDismiss = viewModel::dismissUpdate,
                    )
                }

                if (showScanner) {
                    ScannerOverlay(
                        onDismiss = { showScanner = false },
                        onToken = { token ->
                            showScanner = false
                            requestVpnThen { viewModel.joinByToken(token) }
                        },
                    )
                }

                SnackbarHost(snackbarHost)
            }
        }
    }

    /**
     * 深链接入口。
     *
     * 两种形态：
     *   `phantom://j/<20位令牌>` —— 二维码里的邀请，扫码器或分享链接点开
     *   `phantom://room/<6位房间码>` —— 老的房间码分享链接
     *
     * `onNewIntent` 与 `onCreate` 都要处理：应用已在后台时点链接走前者，
     * 冷启动走后者。只做一边的话会出现「第一次点能进，第二次点没反应」。
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent)
    }

    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.takeIf { it.action == Intent.ACTION_VIEW }?.data ?: return
        if (!data.scheme.equals("phantom", ignoreCase = true)) return

        when (data.host?.lowercase()) {
            "j" -> {
                val token = InviteToken.parse(data.toString()) ?: return
                requestVpnThen { viewModel.joinByToken(token) }
            }
            "room" -> {
                val code = data.pathSegments.firstOrNull()?.uppercase()?.take(6) ?: return
                if (code.length != 6) return
                viewModel.setDraftCode(code)
                requestVpnThen { viewModel.join(code) }
            }
        }
        // 消费掉，避免旋转屏幕重建 Activity 时又加入一次。
        setIntent(Intent(Intent.ACTION_MAIN))
    }

    override fun onResume() {
        super.onResume()
        // 用户可能刚从系统设置回来，把 always-on / 电池优化这两个开关的实际状态重新读一遍。
        viewModel.refreshSystemToggles()
        resumeTick++
    }

    /**
     * 建虚拟网卡前必须先拿到 VPN 授权。已授权时 [VpnService.prepare] 返回 null，
     * 直接往下走；否则弹系统对话框，授权回调里再执行挂起的动作。
     */
    private fun requestVpnThen(action: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            // 已授权：直接执行，不走 pendingAction。
            //
            // 之前这里是 startTunnelService() 再 action()，而 startTunnelService
            // 内部又会 invoke 一次 pendingAction —— 用户上一次取消过授权弹窗时
            // pendingAction 没被清掉，于是「加入房间」和「建房」会同时跑起来，
            // 两条房间流程互相踩。
            pendingAction = null
            startTunnelService()
            action()
        } else {
            pendingAction = action
            vpnPermission.launch(intent)
        }
    }

    /** 只负责起服务。挂起的动作由调用方自己决定何时执行。 */
    private fun startTunnelService() {
        startForegroundService(Intent(this, PhantomVpnService::class.java))
    }

    private fun runPendingAction() {
        val action = pendingAction
        pendingAction = null
        action?.invoke()
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

/**
 * 扫码覆盖层。
 *
 * 用 [Dialog] 而不是全屏页面：扫码是一个瞬时动作，用户扫完（或放弃）就该回到
 * 原来的位置。做成页面就得管返回栈，还会在底栏留下一个不该有的落点。
 */
@Composable
private fun ScannerOverlay(
    onDismiss: () -> Unit,
    onToken: (String) -> Unit,
) {
    val colors = PhantomTheme.colors
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = colors.surface,
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text(
                    text = "扫描邀请二维码",
                    style = MaterialTheme.typography.titleMedium,
                    color = colors.ink,
                )
                QrScanner(onToken = onToken)
                Text(
                    text = "对准房主页面上的二维码。扫到无关的码不会有反应。",
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.ink3,
                )
                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text("取消", color = colors.ember)
                }
            }
        }
    }
}

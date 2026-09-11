package com.buildin1.phantom_p2p

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.EngineClient
import com.buildin1.phantom_p2p.engine.InviteToken
import com.buildin1.phantom_p2p.engine.RecentRoom
import com.buildin1.phantom_p2p.engine.roomCode
import com.buildin1.phantom_p2p.ui.Tab
import com.buildin1.phantom_p2p.ui.screens.SettingsUiState
import com.buildin1.phantom_p2p.update.AppUpdater
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 界面状态持有者。
 *
 * 引擎状态直接从 [EngineClient] 的 StateFlow 转发，不在这里再存一份——
 * 存两份就一定会出现「界面显示已连接、引擎其实已经断了」这类不一致。
 * 这里只拥有引擎不关心的东西：当前标签页、房间码草稿、本机偏好。
 */
class PhantomViewModel(
    val engine: EngineClient,
    private val prefs: PhantomPreferences,
    private val updater: AppUpdater,
) : ViewModel() {

    val connectionState: StateFlow<ConnectionState> = engine.state
    val members = engine.members
    val linkStats = engine.linkStats
    val networkProfile = engine.networkProfile
    val inviteToken = engine.inviteToken
    val inviteError = engine.inviteError
    val diagnostics = engine.diagnostics
    val diagnosticsProgress = engine.diagnosticsProgress
    val diagnosticsError = engine.diagnosticsError

    /** 待处理的版本通告。为 null 时界面不显示任何更新相关内容。 */
    val pendingUpdate = updater.pending

    /** 下载 / 校验 / 安装的进行状态。 */
    val updateState = updater.state

    init {
        // 云端下发的通告转交给更新器。经过这一跳而不是界面直接读引擎，
        // 是因为"忽略了哪一条"属于更新器的状态，不该散在界面里。
        viewModelScope.launch {
            engine.appUpdate.collect { info -> if (info != null) updater.offer(info) }
        }
    }

    /** 系统是否已允许本应用安装 APK。false 时要先去系统设置页授权。 */
    fun canInstallUpdate(): Boolean = updater.canInstallPackages()

    /** 「允许安装未知应用」的系统设置页 Intent；Android 8 以下为 null。 */
    fun unknownSourcesIntent() = updater.unknownSourcesSettingsIntent()

    fun startUpdate() {
        val info = updater.pending.value ?: return
        viewModelScope.launch { updater.download(info) }
    }

    fun dismissUpdate() = updater.dismiss()

    private val _tab = MutableStateFlow(Tab.Connect)
    val tab: StateFlow<Tab> = _tab.asStateFlow()

    private val _draftCode = MutableStateFlow("")
    val draftCode: StateFlow<String> = _draftCode.asStateFlow()

    private val _recentRooms = MutableStateFlow(prefs.recentRooms())
    val recentRooms: StateFlow<List<RecentRoom>> = _recentRooms.asStateFlow()

    private val _settings = MutableStateFlow(prefs.snapshot())
    val settings: StateFlow<SettingsUiState> = _settings.asStateFlow()

    /** 一次性提示（复制成功之类），由 Snackbar 消费后清空。 */
    private val _toast = MutableStateFlow<String?>(null)
    val toast: StateFlow<String?> = _toast.asStateFlow()

    fun selectTab(tab: Tab) { _tab.value = tab }

    fun setDraftCode(code: String) {
        // 房间码只有大写字母与数字，长度封顶 6。在这里归一化而不是在输入控件里，
        // 是因为扫码与深链接也会走这条路。
        // 只认 ASCII：isLetterOrDigit() 下中文也算字母，输入法可能塞进来。
        _draftCode.value = with(InviteToken.Companion) {
            code.uppercase().filter { it.isTokenChar() }.take(6)
        }
    }

    fun join(code: String = _draftCode.value) {
        if (code.length != 6) return
        viewModelScope.launch {
            engine.joinRoom(code)
            rememberRoom(code)
        }
    }

    fun createRoom() {
        viewModelScope.launch {
            engine.createRoom().onSuccess { code ->
                _draftCode.value = code
                rememberRoom(code)
                // 建房后跳到房间页：用户此刻要做的下一件事一定是把房间码发出去。
                _tab.value = Tab.Room
            }
        }
    }

    fun cancel() = viewModelScope.launch { engine.leaveRoom() }
    fun disconnect() = viewModelScope.launch { engine.disconnect() }
    fun retry() = viewModelScope.launch { engine.retry() }
    fun reprobe() = viewModelScope.launch { engine.probeNetwork() }

    fun reportProblem() {
        viewModelScope.launch {
            engine.uploadLogs("用户主动反馈")
                .onSuccess { _toast.value = "日志已上传，感谢反馈" }
                .onFailure { _toast.value = "上传失败，稍后会自动重试" }
        }
    }

    /**
     * 复制房间码。
     *
     * 之前这里只弹了一句「已复制房间码」，**并没有真的往剪贴板写** ——
     * 用户去粘贴才发现是空的。提示必须跟在真实动作后面。
     */
    fun copyRoomCode() {
        val code = connectionState.value.roomCode ?: return
        prefs.copyToClipboard("Phantom 房间码", code)
        // Android 13 起系统自带复制浮层，再弹一次就是重复。
        if (!prefs.systemShowsCopyFeedback) _toast.value = "已复制房间码"
    }

    /** 复制邀请链接（二维码里的那串）。 */
    fun copyInviteLink() {
        val token = engine.inviteToken.value ?: return
        prefs.copyToClipboard("Phantom 邀请链接", token.uri)
        if (!prefs.systemShowsCopyFeedback) _toast.value = "已复制邀请链接"
    }

    /** 索要邀请令牌；房主点开二维码时调用。 */
    fun requestInvite() = viewModelScope.launch { engine.requestInviteToken(refresh = false) }

    /** 作废当前邀请并重新签发 —— 二维码发错群了的补救。 */
    fun refreshInvite() = viewModelScope.launch {
        engine.requestInviteToken(refresh = true)
        _toast.value = "旧邀请已失效，正在生成新的"
    }

    /**
     * 从剪贴板取邀请并加入。
     *
     * 房主分享出去的是一条 `phantom://j/<令牌>` 链接，但链接只在装了本应用的
     * 设备上点得开；从聊天软件复制过来的那串文本此前**没有任何地方能输入** ——
     * 有分享却无处可用。
     *
     * 三种形态都认：整条链接、裸令牌、以及 6 位房间码（用户很可能顺手复制的
     * 就是房间码，直接当房间码用比报错好）。
     *
     * @return 是否成功识别。识别不出时由调用方决定怎么提示。
     */
    fun pasteInvite() {
        val raw = prefs.readClipboardText()
        if (raw.isNullOrEmpty()) {
            _toast.value = "剪贴板是空的"
            return
        }

        InviteToken.parse(raw)?.let { token ->
            joinByToken(token)
            return
        }

        // 退一步：是不是一个 6 位房间码？
        // 只认 ASCII 字母数字 —— isLetterOrDigit() 下中文也算字母，
        // "房间码 AB3K9M" 会被当成有效输入。
        val code = with(InviteToken.Companion) {
            raw.uppercase().filter { it.isTokenChar() }
        }
        if (code.length == 6) {
            setDraftCode(code)
            join(code)
            return
        }

        _toast.value = "剪贴板里不是邀请链接或房间码"
    }

    /**
     * 扫码或深链接拿到令牌后加入房间。
     *
     * 与 [join] 是同一件事的两条入口：令牌只是房间码的另一种载体，
     * 解析在服务端完成，客户端不做任何解码。
     */
    fun joinByToken(token: String) {
        viewModelScope.launch {
            engine.joinByToken(token).onFailure {
                _toast.value = "邀请无效或已失效"
            }
        }
    }
    fun consumeToast() { _toast.value = null }

    fun setRememberRoomCode(value: Boolean) = updateSettings { prefs.setRememberRoomCode(value) }
    fun setAutoConnect(value: Boolean) = updateSettings { prefs.setAutoConnect(value) }
    fun setNotificationActions(value: Boolean) = updateSettings { prefs.setNotificationActions(value) }
    fun refreshSystemToggles() = updateSettings { }

    private fun updateSettings(mutate: () -> Unit) {
        mutate()
        _settings.value = prefs.snapshot()
    }

    private fun rememberRoom(code: String) {
        if (!prefs.rememberRoomCode) return
        prefs.pushRecentRoom(code)
        _recentRooms.value = prefs.recentRooms()
    }
}

package com.buildin1.phantom_p2p

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.EngineClient
import com.buildin1.phantom_p2p.engine.RecentRoom
import com.buildin1.phantom_p2p.ui.Tab
import com.buildin1.phantom_p2p.ui.screens.SettingsUiState
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
) : ViewModel() {

    val connectionState: StateFlow<ConnectionState> = engine.state
    val members = engine.members
    val linkStats = engine.linkStats
    val networkProfile = engine.networkProfile

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
        _draftCode.value = code.uppercase().filter { it.isLetterOrDigit() }.take(6)
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

    fun copyRoomCode() { _toast.value = "已复制房间码" }
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

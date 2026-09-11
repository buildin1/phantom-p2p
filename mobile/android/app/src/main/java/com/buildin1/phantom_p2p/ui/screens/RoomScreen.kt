package com.buildin1.phantom_p2p.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.InviteToken
import com.buildin1.phantom_p2p.engine.PunchPhase
import com.buildin1.phantom_p2p.engine.RoomMember
import com.buildin1.phantom_p2p.engine.Transport
import com.buildin1.phantom_p2p.engine.roomCode
import com.buildin1.phantom_p2p.ui.components.CardLabel
import com.buildin1.phantom_p2p.ui.components.InviteCard
import com.buildin1.phantom_p2p.ui.components.MemberRow
import com.buildin1.phantom_p2p.ui.components.PhantomCard
import com.buildin1.phantom_p2p.ui.components.PreparingBanner
import com.buildin1.phantom_p2p.ui.components.RoomCodeDisplay
import com.buildin1.phantom_p2p.ui.components.RowDivider
import com.buildin1.phantom_p2p.ui.components.RowValue
import com.buildin1.phantom_p2p.ui.components.SettingRow
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

/**
 * 房间页。
 *
 * 三种形态：
 * - 没房间 → 空态
 * - 有房间码但隧道还没建好 → **房间码照常显示 + 进行中横幅**
 * - 已接通 → 完整信息
 *
 * 中间那一态是这一页存在的关键。建房时房间码在服务端应答那一刻就有了，
 * 但隧道还要一两秒。这段时间必须让用户看到：① 房间码（他此刻就要发给队友）
 * ② 一个持续运动的元素（证明没卡死）。少了任何一样，用户都会以为创建失败了。
 */
@Composable
fun RoomScreen(
    state: ConnectionState,
    subnet: String,
    mtu: Int,
    members: List<RoomMember>,
    isHost: Boolean,
    inviteToken: InviteToken?,
    inviteError: String?,
    onCopyCode: () -> Unit,
    onShowQr: () -> Unit,
    onCopyInvite: () -> Unit,
    onRefreshInvite: () -> Unit,
    onLeave: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    val code = state.roomCode
    if (code == null) {
        RoomEmptyState(modifier.padding(contentPadding))
        return
    }

    val preparing = state is ConnectionState.Connecting
    val failed = state is ConnectionState.Failed

    // 二维码展开与否是纯展示状态，没必要上抬到 ViewModel。
    var showInvite by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // 顶/底留白加在滚动容器内部，内容才能从毛玻璃栏杆后面划过去
        Spacer(Modifier.height(contentPadding.calculateTopPadding()))

        PhantomCard {
            CardLabel("房间码 · 分享给队友")
            RoomCodeDisplay(code)

            // 进行中横幅随状态收放，不是硬切 —— 隧道建好那一刻横幅收起、
            // 按钮亮起，是一个连续的动作。
            AnimatedVisibility(
                visible = preparing,
                enter = fadeIn(tween(200)) + expandVertically(tween(240)),
                exit = fadeOut(tween(140)) + shrinkVertically(tween(200)),
            ) {
                PreparingBanner(
                    title = if (isHost) "正在准备房间" else "正在接入房间",
                    subtitle = (state as? ConnectionState.Connecting)
                        ?.phase
                        ?.displayLabel
                        ?.let { "$it · 通常 2 秒内完成" },
                    modifier = Modifier.padding(top = 2.dp),
                )
            }

            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TonalAction("复制", Modifier.weight(1f), onCopyCode)
                // 只有房主能拿邀请令牌（服务端限制：guest 拿到就能无限拉人进
                // 别人的房间），所以 guest 这里不给二维码入口。
                if (isHost) {
                    TonalAction(
                        text = if (showInvite) "收起二维码" else "二维码",
                        modifier = Modifier.weight(1f),
                    ) {
                        showInvite = !showInvite
                        // 展开时才去要令牌。房主建房时已经预先要过一次，
                        // 这里是兜底：那次要是掉了（比如信令刚好在重连），
                        // 用户点开还能补上，而不是对着"正在生成"一直等。
                        if (showInvite && inviteToken == null) onShowQr()
                    }
                }
            }
        }

        AnimatedVisibility(
            visible = isHost && showInvite,
            enter = fadeIn(tween(200)) + expandVertically(tween(240)),
            exit = fadeOut(tween(140)) + shrinkVertically(tween(200)),
        ) {
            InviteCard(
                token = inviteToken,
                error = inviteError,
                onRefresh = onRefreshInvite,
                onCopy = onCopyInvite,
            )
        }

        if (failed) {
            PhantomCard(tonal = true) {
                Text(
                    "房间没能建立起来。回到「连接」页可以重试。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = PhantomTheme.colors.rose,
                )
            }
        }

        PhantomCard {
            CardLabel(
                if (preparing && members.isEmpty()) "成员" else "成员 · ${members.size} 人"
            )
            if (members.isEmpty()) {
                // 还没有成员数据时给一条占位说明，而不是留一块空白 ——
                // 空白读起来像「加载失败」。
                Text(
                    if (preparing) "正在确认成员…" else "还没有人加入",
                    style = MaterialTheme.typography.bodyMedium,
                    color = PhantomTheme.colors.ink2,
                    modifier = Modifier.padding(vertical = 6.dp),
                )
            } else {
                members.forEachIndexed { index, member ->
                    MemberRow(member)
                    if (index != members.lastIndex) RowDivider()
                }
            }
        }

        PhantomCard(tonal = true) {
            SettingRow(title = "虚拟网段", trailing = { RowValue(subnet, mono = true) })
            RowDivider()
            // MTU 与 core 的 TUN_MTU 同源，展示出来是为了排障时不用翻日志。
            SettingRow(title = "MTU", trailing = { RowValue(mtu.toString(), mono = true) })
        }

        OutlinedButton(
            onClick = onLeave,
            modifier = Modifier.fillMaxWidth(),
            border = ButtonDefaults.outlinedButtonBorder.copy(
                brush = SolidColor(PhantomTheme.colors.roseWash),
            ),
        ) {
            Text(
                text = when {
                    preparing -> "取消"
                    isHost -> "关闭房间"
                    else -> "离开房间"
                },
                style = MaterialTheme.typography.titleMedium,
                color = PhantomTheme.colors.rose,
            )
        }

        Spacer(Modifier.height(contentPadding.calculateBottomPadding() + 8.dp))
    }
}

@Composable
private fun TonalAction(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val colors = PhantomTheme.colors
    Button(
        onClick = onClick,
        modifier = modifier,
        colors = ButtonDefaults.buttonColors(
            containerColor = colors.emberWash,
            contentColor = colors.ember,
        ),
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun RoomEmptyState(modifier: Modifier = Modifier) {
    val colors = PhantomTheme.colors
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "还没有加入房间",
            style = MaterialTheme.typography.titleLarge,
            color = colors.ink,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            "在「连接」页输入房间码，或者开一间新的。",
            style = MaterialTheme.typography.bodyMedium,
            color = colors.ink2,
            textAlign = TextAlign.Center,
        )
    }
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

private val previewMembers = listOf(
    RoomMember("self", "这台设备", "10.66.0.2", false, true, null, null),
    RoomMember("chen", "老陈", "10.66.0.1", true, false, 12, Transport.Udp),
    RoomMember("qi", "阿祈", "10.66.0.3", false, false, 28, Transport.Quic),
)

@Preview(name = "创建中", widthDp = 384, heightDp = 760)
@Composable
private fun RoomPreparingPreview() = PhantomPreview {
    RoomScreen(
        state = ConnectionState.Connecting("7K2M9Q", PunchPhase.WaitingPeer, 900),
        subnet = "10.66.0.0/24",
        mtu = 1160,
        members = emptyList(),
        isHost = true,
        inviteToken = InviteToken("7QFK3M2XJ9WD4NBV6RTZ", "7K2M9Q"),
        inviteError = null,
        onCopyCode = {}, onShowQr = {}, onCopyInvite = {}, onRefreshInvite = {}, onLeave = {},
    )
}

@Preview(name = "已接通", widthDp = 384, heightDp = 760)
@Composable
private fun RoomLivePreview() = PhantomPreview {
    RoomScreen(
        state = ConnectionState.Connected("7K2M9Q", Transport.Udp, "10.66.0.2", "10.66.0.1", 0L),
        subnet = "10.66.0.0/24",
        mtu = 1160,
        members = previewMembers,
        isHost = false,
        inviteToken = InviteToken("7QFK3M2XJ9WD4NBV6RTZ", "7K2M9Q"),
        inviteError = null,
        onCopyCode = {}, onShowQr = {}, onCopyInvite = {}, onRefreshInvite = {}, onLeave = {},
    )
}

@Preview(name = "空态 · 深色", widthDp = 384, heightDp = 760)
@Composable
private fun RoomEmptyPreview() = PhantomPreview(dark = true) {
    RoomScreen(
        state = ConnectionState.Idle,
        subnet = "", mtu = 1160, members = emptyList(), isHost = false,
        inviteToken = InviteToken("7QFK3M2XJ9WD4NBV6RTZ", "7K2M9Q"),
        inviteError = null,
        onCopyCode = {}, onShowQr = {}, onCopyInvite = {}, onRefreshInvite = {}, onLeave = {},
    )
}

package com.buildin1.phantom_p2p.ui.screens

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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.LinkStats
import com.buildin1.phantom_p2p.engine.PunchPhase
import com.buildin1.phantom_p2p.engine.RecentRoom
import com.buildin1.phantom_p2p.engine.RoomMember
import com.buildin1.phantom_p2p.engine.Transport
import com.buildin1.phantom_p2p.ui.components.CardLabel
import com.buildin1.phantom_p2p.ui.components.GroupLabel
import com.buildin1.phantom_p2p.ui.components.MemberRow
import com.buildin1.phantom_p2p.ui.components.MetricsRow
import com.buildin1.phantom_p2p.ui.components.Patchbay
import com.buildin1.phantom_p2p.ui.components.PhantomCard
import com.buildin1.phantom_p2p.ui.components.PhaseList
import com.buildin1.phantom_p2p.ui.components.RoomChip
import com.buildin1.phantom_p2p.ui.components.RoomCodeInput
import com.buildin1.phantom_p2p.ui.components.RowDivider
import com.buildin1.phantom_p2p.ui.components.SettingRow
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

/**
 * 连接页。
 *
 * 四个状态共用顶部的接线台构件，下半屏按状态换内容。这是全应用信息密度最低
 * 的一页，故意的：绝大多数用户打开应用只想知道「连上了没有」。
 */
@Composable
fun ConnectScreen(
    state: ConnectionState,
    stats: LinkStats,
    members: List<RoomMember>,
    draftCode: String,
    recentRooms: List<RecentRoom>,
    onDraftClick: () -> Unit,
    onJoin: () -> Unit,
    onCreateRoom: () -> Unit,
    onPickRecent: (String) -> Unit,
    onCancel: () -> Unit,
    onDisconnect: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
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
            Patchbay(
                state = state,
                localLabel = (state as? ConnectionState.Connected)?.localVirtualIp ?: "本机",
                remoteLabel = when (state) {
                    is ConnectionState.Connected -> state.peerVirtualIp
                    is ConnectionState.Connecting -> state.roomCode
                    is ConnectionState.Failed -> state.roomCode ?: "对端"
                    ConnectionState.Idle -> "对端"
                },
            )
        }

        when (state) {
            is ConnectionState.Idle -> IdleBody(
                draftCode = draftCode,
                recentRooms = recentRooms,
                onDraftClick = onDraftClick,
                onJoin = onJoin,
                onCreateRoom = onCreateRoom,
                onPickRecent = onPickRecent,
            )

            is ConnectionState.Connecting -> ConnectingBody(
                phase = state.phase,
                onCancel = onCancel,
            )

            is ConnectionState.Connected -> ConnectedBody(
                stats = stats,
                members = members,
                onDisconnect = onDisconnect,
            )

            is ConnectionState.Failed -> FailedBody(
                roomCode = state.roomCode,
                onRetry = onRetry,
                onBack = onCancel,
            )
        }

        Spacer(Modifier.height(contentPadding.calculateBottomPadding() + 8.dp))
    }
}

// ---------------------------------------------------------------------------

@Composable
private fun IdleBody(
    draftCode: String,
    recentRooms: List<RecentRoom>,
    onDraftClick: () -> Unit,
    onJoin: () -> Unit,
    onCreateRoom: () -> Unit,
    onPickRecent: (String) -> Unit,
) {
    PhantomCard {
        CardLabel("房间码")
        RoomCodeInput(draftCode, onClick = onDraftClick)
        PrimaryButton(
            text = "加入房间",
            enabled = draftCode.length == 6,
            onClick = onJoin,
        )
    }

    if (recentRooms.isNotEmpty()) {
        Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
            GroupLabel("最近的房间")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                recentRooms.take(3).forEach { room ->
                    RoomChip(room.code, room.relativeHint) { onPickRecent(room.code) }
                }
            }
        }
    }

    SecondaryButton(text = "创建房间", onClick = onCreateRoom)
}

@Composable
private fun ConnectingBody(phase: PunchPhase, onCancel: () -> Unit) {
    PhantomCard {
        CardLabel("推进")
        PhaseList(phase)
    }

    PhantomCard(tonal = true) {
        Text(
            text = "首次连接会请求 VPN 权限。系统弹窗里点「确定」即可，" +
                "Phantom 不会读取你的其他流量。",
            style = MaterialTheme.typography.bodySmall,
            color = PhantomTheme.colors.ink2,
        )
    }

    TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
        Text("取消", color = PhantomTheme.colors.ember)
    }
}

@Composable
private fun ConnectedBody(
    stats: LinkStats,
    members: List<RoomMember>,
    onDisconnect: () -> Unit,
) {
    MetricsRow(stats)

    val peers = members.filterNot { it.isSelf }
    if (peers.isNotEmpty()) {
        PhantomCard {
            CardLabel("同房间 · ${peers.size} 人")
            peers.forEachIndexed { index, member ->
                MemberRow(member)
                if (index != peers.lastIndex) RowDivider()
            }
        }
    }

    Button(
        onClick = onDisconnect,
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(
            containerColor = PhantomTheme.colors.roseWash,
            contentColor = PhantomTheme.colors.rose,
        ),
        contentPadding = ButtonDefaults.ContentPadding,
    ) {
        Text("断开连接", style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun FailedBody(roomCode: String?, onRetry: () -> Unit, onBack: () -> Unit) {
    PhantomCard(tonal = true) {
        CardLabel("可以先看看")
        SettingRow(
            title = "对方是否也在这间房",
            subtitle = roomCode?.let { "房间码 $it" } ?: "确认房间码没有输错",
        )
        RowDivider()
        SettingRow(
            title = "切到另一个网络试试",
            subtitle = "部分校园网与公司网会拦截 P2P",
        )
    }

    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.weight(1f),
            border = ButtonDefaults.outlinedButtonBorder.copy(
                brush = SolidColor(PhantomTheme.colors.line),
            ),
        ) {
            Text("返回", color = PhantomTheme.colors.ink)
        }
        Button(
            onClick = onRetry,
            modifier = Modifier.weight(1f),
            colors = ButtonDefaults.buttonColors(
                containerColor = PhantomTheme.colors.ember,
                contentColor = PhantomTheme.colors.onEmber,
            ),
        ) {
            Text("重试")
        }
    }
}

// ---------------------------------------------------------------------------

@Composable
internal fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = PhantomTheme.colors
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(
            containerColor = colors.ember,
            contentColor = colors.onEmber,
            disabledContainerColor = colors.surface2,
            disabledContentColor = colors.ink3,
        ),
    ) {
        Text(text, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
internal fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PhantomTheme.colors
    OutlinedButton(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        border = ButtonDefaults.outlinedButtonBorder.copy(brush = SolidColor(colors.line)),
    ) {
        Text(text, style = MaterialTheme.typography.titleMedium, color = colors.ink)
    }
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

private val previewRecent = listOf(
    RecentRoom("7K2M9Q", "昨天"),
    RecentRoom("3F8D1A", "周二"),
)

@Preview(name = "未连接", widthDp = 384, heightDp = 760)
@Composable
private fun ConnectIdlePreview() = PhantomPreview {
    ConnectScreen(
        state = ConnectionState.Idle,
        stats = LinkStats.EMPTY,
        members = emptyList(),
        draftCode = "7K2M",
        recentRooms = previewRecent,
        onDraftClick = {}, onJoin = {}, onCreateRoom = {}, onPickRecent = {},
        onCancel = {}, onDisconnect = {}, onRetry = {},
    )
}

@Preview(name = "连接中", widthDp = 384, heightDp = 760)
@Composable
private fun ConnectBusyPreview() = PhantomPreview {
    ConnectScreen(
        state = ConnectionState.Connecting("7K2M9Q", PunchPhase.Punching, 1_800),
        stats = LinkStats.EMPTY,
        members = emptyList(),
        draftCode = "7K2M9Q",
        recentRooms = previewRecent,
        onDraftClick = {}, onJoin = {}, onCreateRoom = {}, onPickRecent = {},
        onCancel = {}, onDisconnect = {}, onRetry = {},
    )
}

@Preview(name = "已连接 · 深色", widthDp = 384, heightDp = 760)
@Composable
private fun ConnectLivePreview() = PhantomPreview(dark = true) {
    ConnectScreen(
        state = ConnectionState.Connected("7K2M9Q", Transport.Udp, "10.66.0.2", "10.66.0.1", 0L),
        stats = LinkStats(12, 0.3, 1.2, 3.4, listOf(12, 13, 11, 14, 12)),
        members = listOf(
            RoomMember("self", "这台设备", "10.66.0.2", false, true, null, null),
            RoomMember("chen", "老陈", "10.66.0.1", true, false, 12, Transport.Udp),
            RoomMember("qi", "阿祈", "10.66.0.3", false, false, 28, Transport.Quic),
        ),
        draftCode = "", recentRooms = emptyList(),
        onDraftClick = {}, onJoin = {}, onCreateRoom = {}, onPickRecent = {},
        onCancel = {}, onDisconnect = {}, onRetry = {},
    )
}

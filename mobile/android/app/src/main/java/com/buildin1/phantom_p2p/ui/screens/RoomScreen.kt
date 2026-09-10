package com.buildin1.phantom_p2p.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.RoomMember
import com.buildin1.phantom_p2p.engine.Transport
import com.buildin1.phantom_p2p.ui.components.CardLabel
import com.buildin1.phantom_p2p.ui.components.MemberRow
import com.buildin1.phantom_p2p.ui.components.PhantomCard
import com.buildin1.phantom_p2p.ui.components.RoomCodeDisplay
import com.buildin1.phantom_p2p.ui.components.RowDivider
import com.buildin1.phantom_p2p.ui.components.RowValue
import com.buildin1.phantom_p2p.ui.components.SettingRow
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

/** 房间页。不在房间时显示空态，不是一屏空白卡片。 */
@Composable
fun RoomScreen(
    roomCode: String?,
    subnet: String,
    mtu: Int,
    members: List<RoomMember>,
    isHost: Boolean,
    onCopyCode: () -> Unit,
    onShowQr: () -> Unit,
    onLeave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (roomCode == null) {
        RoomEmptyState(modifier)
        return
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        PhantomCard {
            CardLabel("房间码 · 分享给队友")
            RoomCodeDisplay(roomCode)
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TonalAction("复制", Modifier.weight(1f), onCopyCode)
                TonalAction("二维码", Modifier.weight(1f), onShowQr)
            }
        }

        PhantomCard {
            CardLabel("成员 · ${members.size} 人")
            members.forEachIndexed { index, member ->
                MemberRow(member)
                if (index != members.lastIndex) RowDivider()
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
                text = if (isHost) "关闭房间" else "离开房间",
                style = MaterialTheme.typography.titleMedium,
                color = PhantomTheme.colors.rose,
            )
        }

        Spacer(Modifier.padding(bottom = 8.dp))
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
        horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
    ) {
        Text(
            "还没有加入房间",
            style = MaterialTheme.typography.titleLarge,
            color = colors.ink,
        )
        Spacer(Modifier.padding(top = 6.dp))
        Text(
            "在「连接」页输入房间码，或者开一间新的。",
            style = MaterialTheme.typography.bodyMedium,
            color = colors.ink2,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}

@Preview(widthDp = 384, heightDp = 760)
@Composable
private fun RoomPreview() = PhantomPreview {
    RoomScreen(
        roomCode = "7K2M9Q",
        subnet = "10.66.0.0/24",
        mtu = 1160,
        isHost = false,
        members = listOf(
            RoomMember("self", "这台设备", "10.66.0.2", false, true, null, null),
            RoomMember("chen", "老陈", "10.66.0.1", true, false, 12, Transport.Udp),
            RoomMember("qi", "阿祈", "10.66.0.3", false, false, 28, Transport.Quic),
        ),
        onCopyCode = {}, onShowQr = {}, onLeave = {},
    )
}

@Preview(name = "空态 · 深色", widthDp = 384, heightDp = 760)
@Composable
private fun RoomEmptyPreview() = PhantomPreview(dark = true) {
    RoomScreen(
        roomCode = null, subnet = "", mtu = 1160, members = emptyList(), isHost = false,
        onCopyCode = {}, onShowQr = {}, onLeave = {},
    )
}

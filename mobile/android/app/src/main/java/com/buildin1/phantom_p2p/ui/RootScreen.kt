package com.buildin1.phantom_p2p.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.ConnectionState
import com.buildin1.phantom_p2p.engine.pillLabel
import com.buildin1.phantom_p2p.ui.components.PillTone
import com.buildin1.phantom_p2p.ui.components.StatusPill
import com.buildin1.phantom_p2p.ui.icons.PhantomIcons
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

enum class Tab(val label: String) {
    Connect("连接"),
    Room("房间"),
    Diagnostics("诊断"),
    Settings("设置"),
    ;

    val icon: ImageVector
        get() = when (this) {
            Connect -> PhantomIcons.Link
            Room -> PhantomIcons.Members
            Diagnostics -> PhantomIcons.Pulse
            Settings -> PhantomIcons.Gear
        }
}

/**
 * 应用外壳：顶栏 + 内容 + M3 导航栏。
 *
 * 顶栏只在「连接」页显示状态药丸——其余三页的标题栏用大标题样式，
 * 与设计稿一致；把药丸挂到每一页会让它变成噪音。
 */
@Composable
fun RootScreen(
    selectedTab: Tab,
    onSelectTab: (Tab) -> Unit,
    connectionState: ConnectionState,
    onOpenAppSettings: () -> Unit,
    content: @Composable (Tab) -> Unit,
) {
    val colors = PhantomTheme.colors

    Column(
        Modifier
            .fillMaxSize()
            .background(colors.bg)
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        when (selectedTab) {
            Tab.Connect -> ConnectTopBar(connectionState, onOpenAppSettings)
            else -> LargeTitleBar(selectedTab.label)
        }

        Box(Modifier.weight(1f)) { content(selectedTab) }

        NavigationBar(selectedTab, onSelectTab)
    }
}

@Composable
private fun ConnectTopBar(state: ConnectionState, onOpenAppSettings: () -> Unit) {
    val colors = PhantomTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            "Phantom",
            style = MaterialTheme.typography.titleLarge,
            color = colors.ink,
            modifier = Modifier.weight(1f),
        )
        StatusPill(
            text = state.pillLabel,
            tone = when (state) {
                is ConnectionState.Connected -> PillTone.Ok
                is ConnectionState.Connecting -> PillTone.Busy
                else -> PillTone.Off
            },
        )
        Box(
            Modifier
                .size(40.dp)
                .clip(CircleShape)
                .clickable(onClick = onOpenAppSettings),
            contentAlignment = Alignment.Center,
        ) {
            androidx.compose.material3.Icon(
                imageVector = PhantomIcons.Gear,
                contentDescription = "设置",
                tint = colors.ink2,
                modifier = Modifier.size(24.dp),
            )
        }
    }
}

@Composable
private fun LargeTitleBar(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.headlineLarge,
        color = PhantomTheme.colors.ink,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 18.dp),
    )
}

@Composable
private fun NavigationBar(selected: Tab, onSelect: (Tab) -> Unit) {
    val colors = PhantomTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .background(colors.surface2)
            .padding(top = 12.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Tab.entries.forEach { tab ->
            val active = tab == selected
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier
                    .clip(CircleShape)
                    .clickable { onSelect(tab) }
                    .padding(horizontal = 8.dp),
            ) {
                Box(
                    Modifier
                        .clip(CircleShape)
                        .background(if (active) colors.emberWash else colors.surface2)
                        .padding(horizontal = 20.dp, vertical = 4.dp),
                ) {
                    androidx.compose.material3.Icon(
                        imageVector = tab.icon,
                        contentDescription = tab.label,
                        tint = if (active) colors.ember else colors.ink2,
                        modifier = Modifier.size(24.dp),
                    )
                }
                Text(
                    text = tab.label,
                    style = MaterialTheme.typography.labelMedium,
                    color = if (active) colors.ink else colors.ink2,
                )
            }
        }
    }
}

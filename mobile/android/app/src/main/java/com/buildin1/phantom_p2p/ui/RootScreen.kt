package com.buildin1.phantom_p2p.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.ExperimentalAnimationApi
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
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
import com.buildin1.phantom_p2p.util.rememberReduceMotion
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.materials.HazeMaterials

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
 * 应用外壳。
 *
 * ## 沉浸式布局
 *
 * 整个 Column 铺满屏幕、**不做 safeDrawing 内缩**，内容真的画到状态栏和手势
 * 小白条底下去。系统留白改成加在顶栏/底栏的**内部**：底栏的毛玻璃背景一直
 * 铺到屏幕最底边，图标和文字则被顶到小白条上方。这样滚动内容从小白条后面
 * 划过去，是现在 Android 与 iOS 都在做的观感。
 *
 * ## 毛玻璃
 *
 * 顶栏与底栏用 haze 做背景模糊。Android 12（API 31）以下没有 RenderEffect，
 * haze 会自动退回半透明着色，所以 minSdk 26 上不会崩，只是没有真模糊。
 */
@OptIn(ExperimentalAnimationApi::class)
@Composable
fun RootScreen(
    selectedTab: Tab,
    onSelectTab: (Tab) -> Unit,
    connectionState: ConnectionState,
    onOpenAppSettings: () -> Unit,
    content: @Composable (Tab, PaddingValues) -> Unit,
) {
    val colors = PhantomTheme.colors
    val reduceMotion = rememberReduceMotion()
    val hazeState = remember { HazeState() }

    Box(
        Modifier
            .fillMaxSize()
            .background(colors.bg),
    ) {
        // 内容层：铺满全屏，登记为模糊源。上下留出顶栏/底栏的高度，
        // 让滚动内容能从它们后面经过而不是被裁掉。
        Box(
            Modifier
                .fillMaxSize()
                .hazeSource(hazeState),
        ) {
            AnimatedContent(
                targetState = selectedTab,
                transitionSpec = {
                    if (reduceMotion) {
                        fadeIn(tween(120)) togetherWith fadeOut(tween(120))
                    } else {
                        // 顺着标签栏的方向滑：往右边的标签走，新页从右侧进。
                        // 位移只用 1/8 屏宽 —— 移动端的页面切换要"轻推一下"，
                        // 整屏平移会让人觉得慢。
                        val forward = targetState.ordinal > initialState.ordinal
                        val offset = { w: Int -> if (forward) w / 8 else -w / 8 }
                        (slideInHorizontally(tween(260), offset) + fadeIn(tween(200)))
                            .togetherWith(
                                slideOutHorizontally(tween(260)) { w ->
                                    if (forward) -w / 8 else w / 8
                                } + fadeOut(tween(150))
                            )
                    }
                },
                label = "tab",
            ) { tab ->
                content(
                    tab,
                    PaddingValues(
                        top = TOP_BAR_HEIGHT + WindowInsets.statusBars
                            .asPaddingValues()
                            .calculateTopPadding(),
                        bottom = NAV_BAR_HEIGHT + WindowInsets.navigationBars
                            .asPaddingValues()
                            .calculateBottomPadding(),
                    ),
                )
            }
        }

        // 顶栏：背景（含模糊）铺到屏幕顶边，内容被状态栏高度顶下来
        Box(
            Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .hazeEffect(state = hazeState, style = HazeMaterials.thin())
                .windowInsetsPadding(WindowInsets.statusBars),
        ) {
            when (selectedTab) {
                Tab.Connect -> ConnectTopBar(connectionState, onOpenAppSettings)
                else -> LargeTitleBar(selectedTab.label)
            }
        }

        // 底栏：毛玻璃一直铺到屏幕最底边（小白条后面），图标被顶到小白条上方
        Box(
            Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .hazeEffect(state = hazeState, style = HazeMaterials.regular())
                .windowInsetsPadding(WindowInsets.navigationBars),
        ) {
            NavigationBar(selectedTab, onSelectTab)
        }
    }
}

private val TOP_BAR_HEIGHT = 56.dp
private val NAV_BAR_HEIGHT = 68.dp

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
            Icon(
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
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 14.dp),
    )
}

@Composable
private fun NavigationBar(selected: Tab, onSelect: (Tab) -> Unit) {
    val colors = PhantomTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 8.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Tab.entries.forEach { tab ->
            NavItem(
                tab = tab,
                active = tab == selected,
                onClick = { onSelect(tab) },
            )
        }
    }
}

@Composable
private fun NavItem(tab: Tab, active: Boolean, onClick: () -> Unit) {
    val colors = PhantomTheme.colors

    // 选中指示药丸的颜色补间：直接换色太硬，200ms 的过渡刚好让人看清
    // 焦点是"移动"过去的，而不是凭空跳过去的。
    val indicator by animateColorAsState(
        targetValue = if (active) colors.emberWash else colors.emberWash.copy(alpha = 0f),
        animationSpec = tween(200),
        label = "indicator",
    )
    val tint by animateColorAsState(
        targetValue = if (active) colors.ember else colors.ink2,
        animationSpec = tween(200),
        label = "tint",
    )

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier
            .clip(CircleShape)
            // 去掉涟漪：底栏在毛玻璃上，方形涟漪会把玻璃的质感打断。
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onClick,
            )
            .padding(horizontal = 8.dp),
    ) {
        Box(
            Modifier
                .clip(CircleShape)
                .background(indicator)
                .padding(horizontal = 20.dp, vertical = 4.dp),
        ) {
            Icon(
                imageVector = tab.icon,
                contentDescription = tab.label,
                tint = tint,
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

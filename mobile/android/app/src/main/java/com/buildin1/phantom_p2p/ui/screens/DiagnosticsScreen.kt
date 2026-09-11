package com.buildin1.phantom_p2p.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.ui.PreviewData
import com.buildin1.phantom_p2p.engine.DiagnosticsProgress
import com.buildin1.phantom_p2p.engine.LinkStats
import com.buildin1.phantom_p2p.engine.NetworkDiagnostics
import com.buildin1.phantom_p2p.engine.NetworkProfile
import com.buildin1.phantom_p2p.ui.components.CardLabel
import com.buildin1.phantom_p2p.ui.components.LatencySparkline
import com.buildin1.phantom_p2p.ui.components.MetricsRow
import com.buildin1.phantom_p2p.ui.components.PhantomCard
import com.buildin1.phantom_p2p.ui.components.PillTone
import com.buildin1.phantom_p2p.ui.components.RowDivider
import com.buildin1.phantom_p2p.ui.components.RowValue
import com.buildin1.phantom_p2p.ui.components.SettingRow
import com.buildin1.phantom_p2p.ui.components.StatusPill
import com.buildin1.phantom_p2p.ui.theme.MonoNumber
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme

/**
 * 诊断页。
 *
 * 这是全应用**唯一允许出现技术术语**的地方——界面按约定隐藏了链路的真实性质，
 * 日志和这一页就成了开发者与售后仅有的入口。
 */
@Composable
fun DiagnosticsScreen(
    stats: LinkStats,
    profile: NetworkProfile?,
    diagnostics: NetworkDiagnostics?,
    progress: DiagnosticsProgress?,
    error: String?,
    logSizeText: String,
    onReprobe: () -> Unit,
    onOpenLogs: () -> Unit,
    onReportProblem: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    val colors = PhantomTheme.colors
    val probing = progress != null

    Box(modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Spacer(Modifier.height(contentPadding.calculateTopPadding()))

            // 检测过程必须有一个持续运动的元素。之前这一页从点下「重新检测」
            // 到结果出来的十几秒里毫无变化，用户的结论只能是「按钮坏了」。
            AnimatedVisibility(
                visible = probing,
                enter = fadeIn(tween(180)) + expandVertically(tween(220)),
                exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
            ) {
                ProbeProgressCard(progress)
            }

            AnimatedVisibility(
                visible = error != null && !probing,
                enter = fadeIn(tween(180)) + expandVertically(tween(220)),
                exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
            ) {
                PhantomCard(tonal = true) {
                    CardLabel("检测失败")
                    Text(
                        text = error.orEmpty(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.rose,
                    )
                }
            }

            PhantomCard {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CardLabel("延迟 · 近 60 秒")
                    Text(
                        text = stats.latencyMillis?.let { "$it ms" } ?: "—",
                        style = MonoNumber,
                        color = colors.jade,
                    )
                }
                LatencySparkline(stats.latencyHistory)
            }

            MetricsRow(stats)

            PhantomCard {
                CardLabel("网络环境")
                if (profile == null) {
                    SettingRow(title = "正在探测…", subtitle = "读取 NAT 画像与公网映射")
                } else {
                    SettingRow(
                        title = "NAT 类型",
                        trailing = { RowValue(profile.natClass.displayLabel) },
                    )
                    RowDivider()
                    SettingRow(
                        title = "公网映射",
                        subtitle = if (profile.mappingStable) "多次探测结果一致" else "每次探测都不同",
                        trailing = {
                            StatusPill(
                                text = if (profile.mappingStable) "稳定" else "不稳定",
                                tone = if (profile.mappingStable) PillTone.Ok else PillTone.Warn,
                            )
                        },
                    )
                    RowDivider()
                    SettingRow(
                        title = "IPv6",
                        trailing = { RowValue(if (profile.ipv6Available) "可用" else "不可用") },
                    )
                    RowDivider()
                    SettingRow(
                        title = "虚拟网卡 MTU",
                        trailing = { RowValue(profile.mtu.toString(), mono = true) },
                    )
                }
            }

            if (diagnostics != null) {
                DiagnosticsReport(diagnostics)
            }

            PhantomCard {
                CardLabel("日志")
                SettingRow(
                    title = "本地日志",
                    subtitle = logSizeText,
                    onClick = onOpenLogs,
                    trailing = { Chevron() },
                )
                RowDivider()
                SettingRow(
                    title = "反馈问题",
                    subtitle = "打包并上传日志供排障",
                    onClick = onReportProblem,
                    trailing = { Chevron() },
                )
            }

            // 给 FAB 与底栏让出位置，否则最后一行会被压在底下点不到
            Spacer(Modifier.height(contentPadding.calculateBottomPadding() + 76.dp))
        }

        ExtendedFloatingActionButton(
            // 检测中禁用：重复触发会让两轮进度互相覆盖，进度条来回跳。
            onClick = { if (!probing) onReprobe() },
            containerColor = if (probing) colors.surface3 else colors.ember,
            contentColor = if (probing) colors.ink3 else colors.onEmber,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                // FAB 浮在底栏之上，不能被毛玻璃导航栏压住
                .padding(
                    end = 18.dp,
                    bottom = contentPadding.calculateBottomPadding() + 18.dp,
                ),
        ) {
            Text(
                text = if (probing) "检测中…" else "重新检测",
                style = MaterialTheme.typography.titleMedium,
            )
        }
    }
}

/**
 * 检测进度卡片。
 *
 * 三件事同时给：**做到哪一步了**（阶段名）、**还要多久**（预计秒数）、
 * **一直在动**（进度条 + 呼吸的圆点）。缺任何一样，十几秒的等待都会被
 * 读成卡死 —— 尤其是进度停在某一档不动的那几秒。
 */
@Composable
private fun ProbeProgressCard(progress: DiagnosticsProgress?) {
    val colors = PhantomTheme.colors
    // 进度是跳变下发的（4 → 10 → 30 …），直接画会一格一格蹦。
    // 补间成连续运动，才读得出"在推进"而不是"卡了又跳"。
    val animated by animateFloatAsState(
        targetValue = (progress?.percent ?: 0) / 100f,
        animationSpec = tween(durationMillis = 450),
        label = "probe-progress",
    )

    PhantomCard {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CardLabel("正在检测")
            Text(
                text = "${progress?.percent ?: 0}%",
                style = MonoNumber,
                color = colors.ember,
            )
        }

        Box(
            Modifier
                .fillMaxWidth()
                .padding(top = 10.dp)
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(colors.surface2)
        ) {
            Box(
                Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(animated.coerceIn(0f, 1f))
                    .clip(RoundedCornerShape(3.dp))
                    .background(colors.ember)
            )
        }

        Row(
            Modifier.fillMaxWidth().padding(top = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = progress?.stage.orEmpty(),
                style = MaterialTheme.typography.bodySmall,
                color = colors.ink2,
            )
            val eta = progress?.etaSeconds ?: 0
            if (eta > 0) {
                Text(
                    text = "约 $eta 秒",
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.ink3,
                )
            }
        }
    }
}

/**
 * 完整诊断报告。
 *
 * 字段与 PC 端一一对应 —— 用户拿手机和电脑各测一次，看到的必须是同一套说法。
 */
@Composable
private fun DiagnosticsReport(info: NetworkDiagnostics) {
    val colors = PhantomTheme.colors

    PhantomCard {
        CardLabel("NAT 判定 · ${info.rounds} 轮采样")
        SettingRow(
            title = "NAT 类型",
            subtitle = info.natDifficulty.takeIf { it.isNotEmpty() },
            trailing = { RowValue(info.natType.ifEmpty { "—" }) },
        )
        RowDivider()
        SettingRow(
            title = "映射行为",
            trailing = { RowValue(info.mappingBehavior.ifEmpty { "—" }) },
        )
        RowDivider()
        SettingRow(
            title = "过滤行为",
            trailing = { RowValue(info.filteringBehavior.ifEmpty { "—" }) },
        )
        RowDivider()
        SettingRow(
            title = "端口规律",
            trailing = { RowValue(info.portPattern.ifEmpty { "—" }) },
        )
        RowDivider()
        SettingRow(
            title = "判定置信度",
            trailing = { RowValue(info.confidence.ifEmpty { "—" }) },
        )
    }

    PhantomCard {
        CardLabel("地址")
        SettingRow(
            title = "公网映射",
            trailing = {
                RowValue("${info.externalIp}:${info.externalPort}", mono = true)
            },
        )
        RowDivider()
        SettingRow(
            title = "本机地址",
            trailing = { RowValue("${info.localIp}:${info.localPort}", mono = true) },
        )
        RowDivider()
        SettingRow(
            title = "UPnP",
            subtitle = if (info.upnp) "端口映射已建立" else "路由器未开放或不支持",
            trailing = {
                StatusPill(
                    text = if (info.upnp) "可用 · ${info.upnpPort}" else "不可用",
                    tone = if (info.upnp) PillTone.Ok else PillTone.Warn,
                )
            },
        )
        RowDivider()
        SettingRow(
            title = "IPv6",
            subtitle = info.ipv6Addr.takeIf { it.isNotEmpty() },
            trailing = {
                StatusPill(
                    text = if (info.ipv6) "可用" else "不可用",
                    // IPv6 不可用不是问题，只是少一条路，所以用中性色不是警告色。
                    tone = if (info.ipv6) PillTone.Ok else PillTone.Off,
                )
            },
        )
        RowDivider()
        SettingRow(
            title = "优先协议栈",
            trailing = { RowValue(info.networkPriority.uppercase(), mono = true) },
        )
        RowDivider()
        SettingRow(
            title = "虚拟网卡 MTU",
            trailing = { RowValue(info.mtu.toString(), mono = true) },
        )
    }

    if (info.stunDetails.isNotEmpty()) {
        PhantomCard {
            CardLabel("STUN 采样 · ${info.stunDetails.size} 条")
            Text(
                // A / B 两个 socket 的映射端口是否一致，是判型的直接证据。
                // 把原始采样摆出来，售后不用猜，直接看得到。
                text = "两个 socket 的映射端口一致 = 端点无关映射，打洞好打。",
                style = MaterialTheme.typography.bodySmall,
                color = colors.ink3,
                modifier = Modifier.padding(bottom = 6.dp),
            )
            info.stunDetails.forEachIndexed { index, detail ->
                SettingRow(
                    title = detail.server,
                    subtitle = "第 ${detail.round} 轮 · Socket ${detail.socket}",
                    trailing = {
                        Column(horizontalAlignment = Alignment.End) {
                            RowValue(detail.mapping, mono = true)
                            Text(
                                text = "${detail.rttMillis} ms",
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.ink3,
                            )
                        }
                    },
                )
                if (index != info.stunDetails.lastIndex) RowDivider()
            }
        }
    }
}

@Composable
private fun Chevron() {
    Text("›", style = MaterialTheme.typography.titleLarge, color = PhantomTheme.colors.ink3)
}

@Preview(widthDp = 384, heightDp = 760)
@Composable
private fun DiagnosticsPreview() = PhantomPreview {
    DiagnosticsScreen(
        stats = PreviewData.stats,
        profile = PreviewData.profile,
        diagnostics = PreviewData.diagnostics,
        progress = null,
        error = null,
        logSizeText = "4 个分片 · 6.2 MB",
        onReprobe = {}, onOpenLogs = {}, onReportProblem = {},
    )
}

@Preview(name = "深色", widthDp = 384, heightDp = 760)
@Composable
private fun DiagnosticsDarkPreview() = PhantomPreview(dark = true) {
    DiagnosticsScreen(
        stats = PreviewData.stats,
        profile = PreviewData.profile,
        diagnostics = PreviewData.diagnostics,
        progress = null,
        error = null,
        logSizeText = "4 个分片 · 6.2 MB",
        onReprobe = {}, onOpenLogs = {}, onReportProblem = {},
    )
}

@Preview(name = "检测中", widthDp = 384, heightDp = 760)
@Composable
private fun DiagnosticsProbingPreview() = PhantomPreview {
    DiagnosticsScreen(
        stats = PreviewData.stats,
        profile = PreviewData.profile,
        diagnostics = null,
        progress = DiagnosticsProgress(30, "多 STUN 映射采样 第 2/3 轮", 11),
        error = null,
        logSizeText = "4 个分片 · 6.2 MB",
        onReprobe = {}, onOpenLogs = {}, onReportProblem = {},
    )
}

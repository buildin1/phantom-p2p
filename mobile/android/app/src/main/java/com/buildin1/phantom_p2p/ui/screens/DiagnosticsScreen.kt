package com.buildin1.phantom_p2p.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.buildin1.phantom_p2p.engine.FakeEngineClient
import com.buildin1.phantom_p2p.engine.LinkStats
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
    logSizeText: String,
    onReprobe: () -> Unit,
    onOpenLogs: () -> Unit,
    onReportProblem: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    val colors = PhantomTheme.colors

    Box(modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Spacer(Modifier.height(contentPadding.calculateTopPadding()))

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
            onClick = onReprobe,
            containerColor = colors.ember,
            contentColor = colors.onEmber,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                // FAB 浮在底栏之上，不能被毛玻璃导航栏压住
                .padding(
                    end = 18.dp,
                    bottom = contentPadding.calculateBottomPadding() + 18.dp,
                ),
        ) {
            Text("重新检测", style = MaterialTheme.typography.titleMedium)
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
        stats = FakeEngineClient.PREVIEW_STATS,
        profile = FakeEngineClient.SAMPLE_PROFILE,
        logSizeText = "4 个分片 · 6.2 MB",
        onReprobe = {}, onOpenLogs = {}, onReportProblem = {},
    )
}

@Preview(name = "深色", widthDp = 384, heightDp = 760)
@Composable
private fun DiagnosticsDarkPreview() = PhantomPreview(dark = true) {
    DiagnosticsScreen(
        stats = FakeEngineClient.PREVIEW_STATS,
        profile = FakeEngineClient.SAMPLE_PROFILE,
        logSizeText = "4 个分片 · 6.2 MB",
        onReprobe = {}, onOpenLogs = {}, onReportProblem = {},
    )
}

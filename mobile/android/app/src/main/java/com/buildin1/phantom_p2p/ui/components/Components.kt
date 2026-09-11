package com.buildin1.phantom_p2p.ui.components

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.buildin1.phantom_p2p.engine.LinkStats
import com.buildin1.phantom_p2p.engine.PunchPhase
import com.buildin1.phantom_p2p.engine.RoomMember
import com.buildin1.phantom_p2p.ui.theme.MonoMetric
import com.buildin1.phantom_p2p.ui.theme.MonoNumber
import com.buildin1.phantom_p2p.ui.theme.PhantomPreview
import com.buildin1.phantom_p2p.ui.theme.PhantomTheme
import com.buildin1.phantom_p2p.ui.theme.SectionLabel
import com.buildin1.phantom_p2p.util.rememberReduceMotion

// ---------------------------------------------------------------------------
// 容器
// ---------------------------------------------------------------------------

/** 稿里的标准卡片：surface 底、16dp 圆角、极轻的一层阴影。 */
@Composable
fun PhantomCard(
    modifier: Modifier = Modifier,
    tonal: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    val colors = PhantomTheme.colors
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = if (tonal) colors.surface2 else colors.surface,
        shadowElevation = if (tonal) 0.dp else 1.dp,
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }
}

/** 卡片顶上那行全大写小字。 */
@Composable
fun CardLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = SectionLabel,
        color = PhantomTheme.colors.ink3,
        modifier = modifier,
    )
}

// ---------------------------------------------------------------------------
// 状态药丸
// ---------------------------------------------------------------------------

enum class PillTone { Ok, Busy, Off, Warn }

@Composable
fun StatusPill(text: String, tone: PillTone, modifier: Modifier = Modifier) {
    val colors = PhantomTheme.colors
    val (bg, fg) = when (tone) {
        PillTone.Ok -> colors.jadeWash to colors.jade
        PillTone.Busy -> colors.emberWash to colors.ember
        PillTone.Off -> colors.surface2 to colors.ink2
        PillTone.Warn -> colors.goldWash to colors.gold
    }
    Row(
        modifier = modifier
            .clip(CircleShape)
            .background(bg)
            .padding(horizontal = 11.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(fg))
        Text(text, style = MaterialTheme.typography.labelMedium, color = fg)
    }
}

// ---------------------------------------------------------------------------
// 指标条
// ---------------------------------------------------------------------------

/**
 * 三格指标。值一律等宽——这些数字每秒刷新，不等宽会左右跳。
 * 延迟是唯一染成玉青的一格：它是用户真正关心的那个数。
 */
@Composable
fun MetricsRow(stats: LinkStats, modifier: Modifier = Modifier) {
    val colors = PhantomTheme.colors
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(colors.line),
        horizontalArrangement = Arrangement.spacedBy(1.dp),
    ) {
        Metric(
            value = stats.latencyMillis?.toString() ?: "—",
            label = "延迟 ms",
            highlight = true,
            modifier = Modifier.weight(1f),
        )
        Metric(
            value = stats.lossPercent?.let { "%.1f".format(it) } ?: "—",
            label = "丢包 %",
            modifier = Modifier.weight(1f),
        )
        Metric(
            value = stats.downMbps?.let { "%.1f".format(it) } ?: "—",
            label = "下行 MB/s",
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun Metric(
    value: String,
    label: String,
    modifier: Modifier = Modifier,
    highlight: Boolean = false,
) {
    val colors = PhantomTheme.colors
    Column(
        modifier = modifier
            .background(colors.surface)
            .padding(vertical = 12.dp, horizontal = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(value, style = MonoMetric, color = if (highlight) colors.jade else colors.ink)
        Text(label, style = MaterialTheme.typography.labelSmall, color = colors.ink3)
    }
}

// ---------------------------------------------------------------------------
// 火花线
// ---------------------------------------------------------------------------

/**
 * 延迟曲线。只画一条真实采样，末端加实心点强调当前值——
 * 不加网格、不加坐标轴：这是给人一眼看趋势的，不是给人读数的。
 */
@Composable
fun LatencySparkline(
    history: List<Int>,
    modifier: Modifier = Modifier,
) {
    val colors = PhantomTheme.colors
    androidx.compose.foundation.Canvas(modifier.fillMaxWidth().height(40.dp)) {
        if (history.size < 2) return@Canvas

        val min = (history.min() - 2).coerceAtLeast(0)
        val max = history.max() + 2
        val span = (max - min).coerceAtLeast(1)
        val stepX = size.width / (history.size - 1)
        val inset = 4.dp.toPx()
        val usableH = size.height - inset * 2

        fun pointAt(i: Int): Offset {
            val ratio = (history[i] - min).toFloat() / span
            return Offset(i * stepX, inset + usableH * (1f - ratio))
        }

        val path = androidx.compose.ui.graphics.Path().apply {
            moveTo(pointAt(0).x, pointAt(0).y)
            for (i in 1 until history.size) lineTo(pointAt(i).x, pointAt(i).y)
        }
        drawPath(
            path = path,
            color = colors.jade,
            style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round),
        )
        drawCircle(colors.jade, 3.dp.toPx(), pointAt(history.lastIndex))
    }
}

// ---------------------------------------------------------------------------
// 房间码输入
// ---------------------------------------------------------------------------

/**
 * 六格房间码。
 *
 * 用独立格子而不是单行输入框：粘贴、逐位改、扫码回填都落在同一个构件上，
 * 而且六格本身就告诉用户「一共六位」，不用再写一行提示。
 */
@Composable
fun RoomCodeInput(
    code: String,
    onCodeChange: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PhantomTheme.colors
    val focusRequester = remember { FocusRequester() }
    var focused by remember { mutableStateOf(false) }

    Box(modifier.fillMaxWidth()) {
        // 真正接键盘的输入框藏在后面。六个格子只是它的显示层 ——
        // 这样粘贴、逐位删改、系统的验证码自动填充全部落在同一个控件上。
        BasicTextField(
            value = code,
            onValueChange = { raw ->
                // 房间码只有大写字母与数字，长度封顶 6。
                onCodeChange(raw.uppercase().filter(Char::isLetterOrDigit).take(6))
            },
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Ascii,
                imeAction = ImeAction.Done,
            ),
            singleLine = true,
            modifier = Modifier
                .matchParentSize()
                .focusRequester(focusRequester)
                .onFocusChanged { focused = it.isFocused }
                // 完全透明但仍然可交互；不能用 size(0) —— 那样 IME 不会弹。
                .alpha(0f),
            decorationBox = { /* 显示层在下面自己画 */ },
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                ) { focusRequester.requestFocus() },
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            repeat(6) { index ->
                val ch = code.getOrNull(index)
                // 光标只在获得焦点时显示，否则空框上那圈橙边会让人以为正在输入
                val isCaret = focused && index == code.length.coerceAtMost(5) && code.length < 6
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(58.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (ch == null) colors.surface2 else colors.surface)
                        .then(
                            when {
                                isCaret -> Modifier.border(2.dp, colors.ember, RoundedCornerShape(12.dp))
                                ch != null -> Modifier.border(1.dp, colors.line, RoundedCornerShape(12.dp))
                                else -> Modifier
                            }
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = ch?.toString() ?: "·",
                        style = MonoNumber.copy(fontSize = 24.sp),
                        color = if (ch == null) colors.ink3 else colors.ink,
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 阶段清单
// ---------------------------------------------------------------------------

/**
 * 打洞推进。已完成打勾、进行中闪烁、未开始灰着。
 * 耗时是唯一暴露给用户的技术细节——它能让人判断该等还是该退。
 */
@Composable
fun PhaseList(
    current: PunchPhase,
    modifier: Modifier = Modifier,
) {
    val colors = PhantomTheme.colors
    val reduceMotion = rememberReduceMotion()
    val transition = rememberInfiniteTransition(label = "phase")
    val animatedBlink by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0.25f,
        animationSpec = infiniteRepeatable(tween(1100), RepeatMode.Reverse),
        label = "blink",
    )
    val blink = if (reduceMotion) 1f else animatedBlink

    // 每个阶段的耗时：真实实现由引擎逐段上报，这里按当前阶段推一个近似值，
    // 只是为了让已完成的行有个数字可读。
    val order = PunchPhase.entries
    val currentIndex = order.indexOf(current)

    Column(modifier) {
        order.forEachIndexed { index, phase ->
            val done = index < currentIndex
            val now = index == currentIndex
            Row(
                Modifier.fillMaxWidth().padding(vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Box(Modifier.size(18.dp), contentAlignment = Alignment.Center) {
                    androidx.compose.foundation.Canvas(Modifier.size(18.dp)) {
                        val r = size.minDimension / 2
                        when {
                            done -> {
                                drawCircle(colors.jade, r)
                            }
                            now -> {
                                drawCircle(
                                    colors.ember,
                                    r - 1.dp.toPx(),
                                    style = Stroke(2.dp.toPx()),
                                )
                                drawCircle(
                                    colors.ember.copy(alpha = blink),
                                    3.5.dp.toPx(),
                                )
                            }
                            else -> drawCircle(
                                colors.line,
                                r - 0.75f.dp.toPx(),
                                style = Stroke(1.5.dp.toPx()),
                            )
                        }
                    }
                    if (done) {
                        Text(
                            "✓",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                            ),
                            color = colors.surface,
                        )
                    }
                }

                Text(
                    text = phase.displayLabel,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (index > currentIndex) colors.ink3 else colors.ink,
                    modifier = Modifier.weight(1f),
                )

                Text(
                    text = when {
                        now -> "进行中"
                        done -> "%.1fs".format(APPROX_STEP_SECONDS[index])
                        else -> "—"
                    },
                    style = MonoNumber.copy(fontSize = 11.5.sp),
                    color = if (now) colors.ember else colors.ink3,
                )
            }
        }
    }
}

/**
 * 已完成阶段显示的耗时。
 *
 * 目前是占位常数：真实值应由引擎逐段上报（core 的 `punch::Session` 本来就在记）。
 * FFI 落地时把它换成 `PunchPhase -> 实测毫秒` 的映射，别让这几个数字一直假下去——
 * 它们是用户判断「该等还是该退」的唯一依据。
 */
private val APPROX_STEP_SECONDS = listOf(0.4, 0.9, 1.1, 0.5)

// ---------------------------------------------------------------------------
// 成员行
// ---------------------------------------------------------------------------

@Composable
fun MemberRow(member: RoomMember, modifier: Modifier = Modifier) {
    val colors = PhantomTheme.colors
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(if (member.isSelf) colors.emberWash else colors.surface2),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (member.isSelf) "我" else member.displayName.take(1),
                style = MaterialTheme.typography.titleMedium,
                color = if (member.isSelf) colors.ember else colors.ink2,
            )
        }

        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                Text(
                    member.displayName,
                    style = MaterialTheme.typography.bodyLarge,
                    color = colors.ink,
                )
                if (member.isHost) {
                    Text(
                        text = "房主",
                        style = MaterialTheme.typography.labelSmall,
                        color = colors.ember,
                        modifier = Modifier
                            .clip(CircleShape)
                            .background(colors.emberWash)
                            .padding(horizontal = 7.dp, vertical = 1.dp),
                    )
                }
            }
            Text(member.virtualIp, style = MonoNumber.copy(fontSize = 12.5.sp), color = colors.ink2)
        }

        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = member.latencyMillis?.let { "$it ms" } ?: "—",
                style = MonoNumber,
                color = colors.ink,
            )
            Text(
                // 这里印的是传输后缀（UDP / QUIC），不是「直连 / 中继」。
                // 界面任何位置不出现「中继」二字，见 Transport 的文档。
                text = member.transport?.shortLabel ?: if (member.isSelf) "本机" else "—",
                style = MaterialTheme.typography.labelSmall,
                color = colors.ink3,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 设置行
// ---------------------------------------------------------------------------

@Composable
fun SettingRow(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    onClick: (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    val colors = PhantomTheme.colors
    Row(
        modifier = modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = colors.ink)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = colors.ink2)
            }
        }
        trailing?.invoke()
    }
}

/** 行内静态值（右对齐的灰字），可选等宽。 */
@Composable
fun RowValue(text: String, mono: Boolean = false) {
    Text(
        text = text,
        style = if (mono) MonoNumber else MaterialTheme.typography.bodyMedium,
        color = PhantomTheme.colors.ink2,
    )
}

/** 分组之间那行全大写小标题（卡片外部）。 */
@Composable
fun GroupLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = SectionLabel,
        color = PhantomTheme.colors.ink3,
        modifier = modifier.padding(start = 4.dp, top = 4.dp),
    )
}

/** 分隔线。列表最后一行不画。 */
@Composable
fun RowDivider() {
    Box(
        Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(PhantomTheme.colors.lineSoft),
    )
}

/**
 * 房间码历史芯片。
 *
 * 参数顺序按 Compose 惯例：必填在前、`modifier` 作为第一个可选参数、
 * 回调放最后 —— 这样尾随 lambda 才会绑到 [onClick] 而不是 `modifier`。
 */
@Composable
fun RoomChip(
    code: String,
    hint: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val colors = PhantomTheme.colors
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, colors.line, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 13.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Text(code, style = MonoNumber.copy(fontSize = 13.sp), color = colors.ink)
        Text(hint, style = MaterialTheme.typography.labelSmall, color = colors.ink3)
    }
}

/** 大房间码。字距拉开，念给队友听时不容易读错。 */
@Composable
fun RoomCodeDisplay(code: String, modifier: Modifier = Modifier) {
    Text(
        text = code,
        style = com.buildin1.phantom_p2p.ui.theme.RoomCodeStyle,
        color = PhantomTheme.colors.ink,
        textAlign = TextAlign.Center,
        modifier = modifier.fillMaxWidth(),
    )
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

@Preview(widthDp = 360, name = "构件总览")
@Composable
private fun ComponentsPreview() = PhantomPreview {
    Column(
        Modifier.padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatusPill("已连接", PillTone.Ok)
            StatusPill("连接中", PillTone.Busy)
            StatusPill("未连接", PillTone.Off)
            StatusPill("未开启", PillTone.Warn)
        }
        MetricsRow(
            LinkStats(12, 0.3, 1.2, 3.4, listOf(14, 12, 15, 11, 13, 10, 12)),
        )
        RoomCodeInput("7K2M", onCodeChange = {})
        PhantomCard {
            CardLabel("推进")
            PhaseList(PunchPhase.Punching)
        }
        Box(Modifier.width(200.dp)) {
            LatencySparkline(listOf(14, 13, 15, 12, 14, 11, 13, 10, 14, 12, 15, 11, 13))
        }
    }
}

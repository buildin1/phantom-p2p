package com.buildin1.phantom_p2p

import android.os.Bundle
import android.text.Editable
import android.text.InputFilter
import android.text.TextWatcher
import android.view.KeyEvent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TableRow
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.buildin1.phantom_p2p.databinding.FragmentRoomBinding
import com.buildin1.phantom_p2p.signal.RoomTransport

class RoomFragment : Fragment() {

    private var _binding: FragmentRoomBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()

    private var selectedTransport = RoomTransport.TCP
    private var currentPortPage = 0
    private val portsPerPage = 20
    private var allPorts: List<Int> = emptyList()

    // 防止删除重入导致无限循环
    private var suppressWatcher = false
    // Fragment 页面导航退出后保留房间码
    private var savedRoomCode: String = ""
    // 追踪上次的 joining 状态，避免重复触发动画
    private var lastIsJoining: Boolean = false
    // 6-box code input boxes
    private val codeBoxes get() = listOf(
        binding.codeBox1, binding.codeBox2, binding.codeBox3,
        binding.codeBox4, binding.codeBox5, binding.codeBox6
    )

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentRoomBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setupProtocolSegment()
        setupMultiPortToggle()
        setupCodeBoxes()
        setupButtons()
        observeViewModel()

        // 恢复导航前输入的房间码
        if (savedRoomCode.isNotEmpty()) {
            val chars = savedRoomCode.take(6)
            chars.forEachIndexed { i, ch -> codeBoxes[i].setText(ch.toString()) }
        }
    }

    // ──────────────────────────────────────────────
    // Setup
    // ──────────────────────────────────────────────

    private fun setupProtocolSegment() {
        selectedTransport = if (BuildConfig.FLAVOR == "dev" && viewModel.settings.value?.preferUdp == true) {
            RoomTransport.UDP
        } else {
            RoomTransport.TCP
        }
        updateProtoSegment(selectedTransport)
        binding.btnProtoTcp.setOnClickListener {
            selectedTransport = RoomTransport.TCP
            updateProtoSegment(RoomTransport.TCP)
        }
        binding.btnProtoUdp.setOnClickListener {
            selectedTransport = RoomTransport.UDP
            updateProtoSegment(RoomTransport.UDP)
        }
    }

    private fun updateProtoSegment(selected: RoomTransport) {
        val ctx = requireContext()
        val activeTextColor = ContextCompat.getColor(ctx, R.color.segmentTextActive)
        val inactiveTextColor = ContextCompat.getColor(ctx, R.color.segmentText)
        val activeDrawable = ContextCompat.getDrawable(ctx, R.drawable.bg_segment_active)
        if (selected == RoomTransport.TCP) {
            binding.btnProtoTcp.setTextColor(activeTextColor)
            binding.btnProtoTcp.background = activeDrawable
            binding.btnProtoUdp.setTextColor(inactiveTextColor)
            binding.btnProtoUdp.background = null
        } else {
            binding.btnProtoUdp.setTextColor(activeTextColor)
            binding.btnProtoUdp.background = activeDrawable
            binding.btnProtoTcp.setTextColor(inactiveTextColor)
            binding.btnProtoTcp.background = null
        }
    }

    private fun setupMultiPortToggle() {
        binding.switchMultiPort.setOnCheckedChangeListener { _, checked ->
            viewModel.setMultiPort(checked)
            binding.advancedPanel.visibility = if (checked) View.VISIBLE else View.GONE
        }
        binding.btnParsePort.setOnClickListener {
            val spec = binding.etPortSpec.text.toString().trim()
            val count = viewModel.parseAndSetPorts(spec)
            if (count > 0) {
                Toast.makeText(requireContext(), "已解析 $count 个端口", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(requireContext(), "端口格式无效", Toast.LENGTH_SHORT).show()
            }
        }
        binding.btnPortPrev.setOnClickListener {
            if (currentPortPage > 0) {
                currentPortPage--
                renderPortTable()
            }
        }
        binding.btnPortNext.setOnClickListener {
            val maxPage = ((allPorts.size - 1) / portsPerPage)
            if (currentPortPage < maxPage) {
                currentPortPage++
                renderPortTable()
            }
        }
    }

    private fun setupCodeBoxes() {
        codeBoxes.forEachIndexed { index, box ->
            // 代码层限制每格最多 1 个字符（XML 已移除 maxLength，局部处理粘贴）
            box.filters = arrayOf(InputFilter.LengthFilter(1))

            box.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    if (suppressWatcher) return

                    // 当用户粘贴多个字符时， InputFilter.LengthFilter(1) 会截断字符串。
                    // 我们在粘贴前知道完整内容，通过剔除长度限制、读取副本板、再恢复限制来实现。
                    // 但实际上 Android 的 InputFilter 屈层将天然截断粘贴内容。
                    // 因此我们改用另一种方式：移除 InputFilter，自己做分发。
                    val raw = s?.toString() ?: return
                    val text = raw.uppercase().filter { it.isLetterOrDigit() }

                    when {
                        text.length > 1 -> {
                            // 粘贴场景：将内容分发到当前格及后续格
                            suppressWatcher = true
                            text.forEachIndexed { charIdx, ch ->
                                val targetIdx = index + charIdx
                                if (targetIdx < codeBoxes.size) {
                                    codeBoxes[targetIdx].filters = arrayOf()  // 临时移除限制
                                    codeBoxes[targetIdx].setText(ch.toString())
                                    codeBoxes[targetIdx].setSelection(1)
                                    codeBoxes[targetIdx].filters = arrayOf(InputFilter.LengthFilter(1))  // 恢复
                                }
                            }
                            suppressWatcher = false
                            val nextIdx = minOf(index + text.length, codeBoxes.size - 1)
                            codeBoxes[nextIdx].requestFocus()
                        }
                        text.length == 1 -> {
                            // 单字符输入：如需归一化（小写转大写）
                            if (text != raw) {
                                suppressWatcher = true
                                box.setText(text)
                                box.setSelection(1)
                                suppressWatcher = false
                            }
                            if (index < codeBoxes.size - 1) codeBoxes[index + 1].requestFocus()
                        }
                        // text.length == 0: 删除已处理，不需要操作
                    }
                }
            })
            box.setOnKeyListener { _, keyCode, event ->
                if (event.action == KeyEvent.ACTION_DOWN && keyCode == KeyEvent.KEYCODE_DEL) {
                    if (box.text.isEmpty() && index > 0) {
                        codeBoxes[index - 1].requestFocus()
                        codeBoxes[index - 1].text.clear()
                        return@setOnKeyListener true
                    }
                }
                false
            }
        }
    }

    private fun setupButtons() {
        binding.btnCreateRoom.setOnClickListener {
            val state = viewModel.state.value ?: return@setOnClickListener
            val settings = viewModel.settings.value ?: return@setOnClickListener
            if (state.useMultiPort && state.advancedPorts.isNotEmpty()) {
                viewModel.createAdvancedRoom(state.advancedPorts, state.advancedMainPort, selectedTransport)
            } else {
                val gamePort = binding.etGamePort.text.toString().toIntOrNull() ?: settings.gamePort
                viewModel.createRoom(gamePort, selectedTransport)  // 传递当前选择的协议
            }
        }

        binding.btnJoinRoom.setOnClickListener {
            val code = codeBoxes.joinToString("") { it.text.toString() }
            if (code.length < 6) {
                Toast.makeText(requireContext(), "请输入完整的6位房间码", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            binding.btnJoinRoom.isEnabled = false
            viewModel.joinRoom(code)
        }

        binding.btnCopyCode.setOnClickListener {
            val code = viewModel.state.value?.roomCode ?: return@setOnClickListener
            val clipboard = requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("room_code", code))
            Toast.makeText(requireContext(), "房间码已复制", Toast.LENGTH_SHORT).show()
        }

        binding.btnCloseRoom.setOnClickListener {
            viewModel.closeRoom()
        }
    }

    private fun observeViewModel() {
        viewModel.state.observe(viewLifecycleOwner) { state ->
            // 加入房间状态 crossfade
            val isJoining = state.isJoining
            if (isJoining != lastIsJoining) {
                lastIsJoining = isJoining
                if (isJoining) {
                    binding.tvJoiningCode.text = codeBoxes.joinToString("") { it.text.toString() }
                    crossfadeTo(binding.joiningStateContent, binding.joinInputContent)
                } else if (!state.guestActive) {
                    // 仅失败时才反向 crossfade 回输入区；成功时 guestActive=true，连接区整个隐藏
                    crossfadeTo(binding.joinInputContent, binding.joiningStateContent)
                } else {
                    // 连接成功，直接隐藏 joining 卡片，无需 crossfade
                    binding.joiningStateContent.visibility = View.GONE
                    binding.joinInputContent.visibility = View.GONE
                }
            }
            binding.btnJoinRoom.isEnabled = !isJoining && !state.guestActive

            // Host room panel
            if (state.hostActive && state.roomCode != null) {
                binding.tvSectionMyRoom.visibility = View.VISIBLE
                binding.cardMyRoom.visibility = View.VISIBLE
                binding.tvRoomCode.text = state.roomCode
                binding.tvTransportBadge.text = state.roomTransport.name
            } else {
                binding.tvSectionMyRoom.visibility = View.GONE
                binding.cardMyRoom.visibility = View.GONE
            }

            // Guest port panel
            if (state.guestActive && state.isAdvancedMode && state.portTunnelStatus.isNotEmpty()) {
                binding.guestPortPanel.visibility = View.VISIBLE
                renderGuestPortList(state)
            } else {
                binding.guestPortPanel.visibility = View.GONE
            }

            // Port table
            if (state.advancedPorts != allPorts) {
                allPorts = state.advancedPorts
                currentPortPage = 0
                renderPortTable()
            }

            // Sync multi-port toggle
            binding.switchMultiPort.isChecked = state.useMultiPort
            binding.advancedPanel.visibility = if (state.useMultiPort) View.VISIBLE else View.GONE

            // Hero status
            val isActive = state.hostActive || state.guestActive
            binding.tvStatusLabel.text = if (isActive) "已激活" else "未连接"
            if (isActive) {
                binding.statusPill.background = ContextCompat.getDrawable(requireContext(), R.drawable.bg_status_pill_ok)
                binding.tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.pillOkText))
                binding.dotStatus.background = ContextCompat.getDrawable(requireContext(), R.drawable.bg_dot_ok)
            } else {
                binding.statusPill.background = ContextCompat.getDrawable(requireContext(), R.drawable.bg_status_pill_offline)
                binding.tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.pillOfflineText))
                binding.dotStatus.background = ContextCompat.getDrawable(requireContext(), R.drawable.bg_dot_offline)
            }
        }
    }

    private fun renderPortTable() {
        val tableBody = binding.portTableBody
        tableBody.removeAllViews()
        if (allPorts.isEmpty()) {
            binding.portPagination.visibility = View.GONE
            return
        }
        val start = currentPortPage * portsPerPage
        val end = minOf(start + portsPerPage, allPorts.size)
        val pagePorts = allPorts.subList(start, end)
        pagePorts.forEachIndexed { localIndex, port ->
            val globalIndex = start + localIndex + 1
            val row = TableRow(requireContext())
            val numTv = TextView(requireContext()).apply {
                text = globalIndex.toString()
                textSize = 12f
                setPadding(8, 6, 8, 6)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.textMuted))
            }
            val portTv = TextView(requireContext()).apply {
                text = port.toString()
                textSize = 13f
                setPadding(8, 6, 8, 6)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.colorPrimary))
                typeface = android.graphics.Typeface.MONOSPACE
            }
            row.addView(numTv)
            row.addView(portTv)
            tableBody.addView(row)
        }
        val totalPages = ((allPorts.size - 1) / portsPerPage) + 1
        if (totalPages > 1) {
            binding.portPagination.visibility = View.VISIBLE
            binding.tvPortPageInfo.text = "${currentPortPage + 1} / $totalPages"
            binding.btnPortPrev.isEnabled = currentPortPage > 0
            binding.btnPortNext.isEnabled = currentPortPage < totalPages - 1
        } else {
            binding.portPagination.visibility = View.GONE
        }
    }

    private fun renderGuestPortList(state: AppState) {
        val container = binding.guestPortList
        container.removeAllViews()
        state.portTunnelStatus.forEach { (port, status) ->
            val row = TextView(requireContext()).apply {
                text = "端口 $port — ${if (status == PortStatus.READY) "就绪 ✓" else "等待中…"}"
                textSize = 13f
                setPadding(0, 6, 0, 6)
                setTextColor(
                    ContextCompat.getColor(
                        requireContext(),
                        if (status == PortStatus.READY) R.color.colorOk else R.color.textMuted
                    )
                )
                typeface = android.graphics.Typeface.MONOSPACE
            }
            container.addView(row)
        }
    }

    /** 将 [show] 淡入、[hide] 淡出，两段动画交叠 200ms 形成 crossfade */
    private fun crossfadeTo(show: View, hide: View) {
        show.alpha = 0f
        show.visibility = View.VISIBLE
        show.animate().alpha(1f).setDuration(220).start()
        hide.animate().alpha(0f).setDuration(220).withEndAction {
            hide.visibility = View.GONE
            hide.alpha = 1f  // 恢复 alpha，以便下次再次显示时正常
        }.start()
    }

    override fun onDestroyView() {
        // 保存当前已输入的房间码，防止导航后丢失
        savedRoomCode = codeBoxes.joinToString("") { it.text.toString() }
        super.onDestroyView()
        _binding = null
    }
}

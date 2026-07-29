package com.buildin1.phantom_p2p

import android.os.Bundle
import android.view.KeyEvent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsAnimationCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.buildin1.phantom_p2p.databinding.FragmentRoomBinding

class RoomFragment : Fragment() {
    private var _binding: FragmentRoomBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()
    private var savedRoomCode = ""
    private var suppressWatcher = false
    private var lastIsJoining = false

    private val codeBoxes get() = listOf(
        binding.codeBox1, binding.codeBox2, binding.codeBox3,
        binding.codeBox4, binding.codeBox5, binding.codeBox6
    )

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, state: Bundle?): View {
        _binding = FragmentRoomBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, state: Bundle?) {
        super.onViewCreated(view, state)
        setupCodeBoxes()
        setupButtons()
        observeState()
        setupKeyboardInsets()
        binding.rowProtocol.visibility = View.GONE
        binding.rowGamePort.visibility = View.GONE
        binding.rowMultiPort.visibility = View.GONE
        binding.advancedPanel.visibility = View.GONE
        binding.inlineHostIpCard.visibility = View.GONE
        binding.topHostIpCard.visibility = View.VISIBLE
        val prefillCode = savedRoomCode.ifBlank { viewModel.lastRoomCode.orEmpty() }
        prefillCode.take(6).forEachIndexed { index, char -> codeBoxes[index].setText(char.toString()) }
        updateLastRoomEntry()
    }

    private fun setupCodeBoxes() {
        codeBoxes.forEachIndexed { index, box ->
            box.filters = arrayOf(android.text.InputFilter.LengthFilter(1))
            box.setOnFocusChangeListener { _, hasFocus -> if (hasFocus) box.selectAll() }
            box.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
                override fun afterTextChanged(value: android.text.Editable?) {
                    if (suppressWatcher) return
                    val normalized = value?.toString()?.uppercase()?.filter { it.isLetterOrDigit() }.orEmpty()
                    if (normalized != value?.toString()) {
                        suppressWatcher = true
                        box.setText(normalized.take(1))
                        box.setSelection(box.length())
                        suppressWatcher = false
                    }
                    if (box.length() == 1 && index < codeBoxes.lastIndex) codeBoxes[index + 1].requestFocus()
                }
            })
            box.setOnKeyListener { _, keyCode, event ->
                if (keyCode == KeyEvent.KEYCODE_DEL && event.action == KeyEvent.ACTION_DOWN && box.text.isEmpty() && index > 0) {
                    codeBoxes[index - 1].requestFocus()
                    codeBoxes[index - 1].text.clear()
                    true
                } else false
            }
        }
    }

    private fun setupButtons() {
        binding.btnCreateRoom.setOnClickListener { viewModel.createRoom() }
        binding.btnJoinRoom.setOnClickListener {
            val code = codeBoxes.joinToString("") { it.text.toString() }
            if (code.length < 6) {
                Toast.makeText(requireContext(), "请输入完整的 6 位房间码", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            viewModel.joinRoom(code)
        }
        binding.btnCopyCode.setOnClickListener {
            val code = viewModel.state.value?.roomCode ?: return@setOnClickListener
            val clipboard = requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("room_code", code))
            Toast.makeText(requireContext(), "房间码已复制", Toast.LENGTH_SHORT).show()
        }
        binding.btnCloseRoom.setOnClickListener { viewModel.closeRoom() }
        binding.btnAutoJoinLastRoom.setOnClickListener {
            val code = viewModel.lastRoomCode ?: return@setOnClickListener
            suppressWatcher = true
            code.take(6).forEachIndexed { index, char -> codeBoxes[index].setText(char.toString()) }
            suppressWatcher = false
            viewModel.autoJoinLastRoom()
        }
        val fixedIpClick = View.OnClickListener {
            val fixedIp = viewModel.state.value?.fixedHostIp
            if (fixedIp == null) {
                viewModel.toggleFixedHostIp()
            } else {
                com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                    .setTitle("放弃固定 IP")
                    .setMessage("放弃后，$fixedIp 将被释放，后续创建房间会恢复使用动态 IP。")
                    .setNegativeButton("取消", null)
                    .setPositiveButton("确认放弃") { _, _ -> viewModel.toggleFixedHostIp() }
                    .show()
            }
        }
        binding.btnRequestFixedIp.setOnClickListener(fixedIpClick)
        binding.btnTopRequestFixedIp.setOnClickListener(fixedIpClick)
    }

    private fun observeState() {
        viewModel.state.observe(viewLifecycleOwner) { state ->
            val joining = state.isJoining
            if (joining != lastIsJoining) {
                lastIsJoining = joining
                if (joining) {
                    binding.tvJoiningCode.text = codeBoxes.joinToString("") { it.text.toString() }
                    crossfadeTo(binding.joiningStateContent, binding.joinInputContent)
                } else if (!state.guestActive) {
                    crossfadeTo(binding.joinInputContent, binding.joiningStateContent)
                } else {
                    binding.joiningStateContent.visibility = View.GONE
                    binding.joinInputContent.visibility = View.GONE
                }
            }
            binding.btnJoinRoom.isEnabled = !state.isJoining && !state.guestActive
            updateLastRoomEntry()
            binding.tvRoomCode.text = state.roomCode ?: "------"
            binding.tvTransportBadge.text = state.connectionMode.ifBlank { "等待连接" }
            val roomActive = state.roomCode != null
            binding.tvSectionMyRoom.visibility = if (state.hostActive) View.VISIBLE else View.GONE
            binding.cardMyRoom.visibility = if (state.hostActive) View.VISIBLE else View.GONE
            // Once a room exists, the create/join entry cards must disappear.
            (binding.btnCreateRoom.parent as? View)?.visibility = if (roomActive) View.GONE else View.VISIBLE
            (binding.btnJoinRoom.parent?.parent as? View)?.visibility = if (roomActive) View.GONE else View.VISIBLE
            binding.btnRequestFixedIp.text = when {
                state.fixedIpBusy -> "处理中…"
                state.fixedHostIp != null -> "放弃固定 IP"
                else -> "申请固定 IP"
            }
            binding.btnRequestFixedIp.isEnabled = !state.fixedIpBusy
            binding.btnTopRequestFixedIp.text = binding.btnRequestFixedIp.text
            binding.btnTopRequestFixedIp.isEnabled = !state.fixedIpBusy
            val hostIp = state.fixedHostIp ?: state.virtualIp.ifBlank { "127.0.0.1" }
            val ipMode = when {
                state.fixedHostIp != null -> "固定 IP"
                state.virtualIp.isNotBlank() -> "动态 IP"
                else -> "未开房间"
            }
            binding.tvHostVirtualIp.text = hostIp
            binding.tvHostIpMode.text = ipMode
            binding.tvTopHostVirtualIp.text = hostIp
            binding.tvTopHostIpMode.text = ipMode
        }
    }

    /** 展示/隐藏"上次房间：一键连接"入口。仅在不处于加入流程中且存在持久化房间号时显示。 */
    private fun updateLastRoomEntry() {
        if (_binding == null) return
        val last = viewModel.lastRoomCode
        val joining = viewModel.state.value?.isJoining == true
        val show = !last.isNullOrBlank() && !joining
        binding.lastRoomEntry.visibility = if (show) View.VISIBLE else View.GONE
        binding.tvLastRoomCode.text = last ?: "------"
    }

    private fun setupKeyboardInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom
            view.setPadding(view.paddingLeft, view.paddingTop, view.paddingRight, maxOf(104, ime + bars + 24))
            if (ime > 0) view.post { (view as? android.widget.ScrollView)?.smoothScrollTo(0, binding.joinInputContent.bottom) }
            insets
        }
        ViewCompat.setWindowInsetsAnimationCallback(
            binding.root,
            object : WindowInsetsAnimationCompat.Callback(DISPATCH_MODE_CONTINUE_ON_SUBTREE) {
                override fun onProgress(insets: WindowInsetsCompat, runningAnimations: MutableList<WindowInsetsAnimationCompat>): WindowInsetsCompat {
                    ViewCompat.onApplyWindowInsets(binding.root, insets)
                    return insets
                }
            }
        )
        ViewCompat.requestApplyInsets(binding.root)
    }

    private fun crossfadeTo(show: View, hide: View) {
        show.alpha = 0f
        show.visibility = View.VISIBLE
        show.animate().alpha(1f).setDuration(220).start()
        hide.animate().alpha(0f).setDuration(220).withEndAction {
            hide.visibility = View.GONE
            hide.alpha = 1f
        }.start()
    }

    override fun onDestroyView() {
        savedRoomCode = codeBoxes.joinToString("") { it.text.toString() }
        super.onDestroyView()
        _binding = null
    }
}

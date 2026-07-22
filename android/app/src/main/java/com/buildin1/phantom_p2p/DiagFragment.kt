package com.buildin1.phantom_p2p

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.buildin1.phantom_p2p.databinding.FragmentDiagBinding
import com.buildin1.phantom_p2p.databinding.ItemLogBinding
import com.buildin1.phantom_p2p.databinding.ItemStunMappingBinding

class DiagFragment : Fragment() {

    private var _binding: FragmentDiagBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()

    private val stunAdapter = StunMappingsAdapter()
    private val logAdapter = LogAdapter()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentDiagBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.rvStunMappings.layoutManager = LinearLayoutManager(requireContext())
        binding.rvStunMappings.adapter = stunAdapter

        binding.rvLogs.layoutManager = LinearLayoutManager(requireContext()).also {
            it.stackFromEnd = true
        }
        binding.rvLogs.adapter = logAdapter

        binding.btnRunDiag.setOnClickListener {
            viewModel.runDiagnosis()
        }

        binding.btnCopyDiag.setOnClickListener {
            val state = viewModel.state.value ?: return@setOnClickListener
            val sb = StringBuilder()
            sb.appendLine("=== Phantom P2P 网络诊断 ===")
            sb.appendLine("日志文件: ${viewModel.getLogFilePath()}")
            sb.appendLine("NAT 类型: ${state.natType}")
            sb.appendLine("Mapping: ${state.mappingBehavior}")
            sb.appendLine("Filtering: ${state.filteringBehavior}")
            sb.appendLine("端口规律: ${state.portPattern}")
            sb.appendLine("置信度: ${state.confidence}")
            sb.appendLine("公网地址: ${state.publicAddress}")
            sb.appendLine("网络优先级: ${state.networkPriority}")
            state.stunMappings.forEachIndexed { i, m ->
                sb.appendLine("STUN ${i + 1}: ${m.server} → ${m.mapping}  RTT=${m.rttMs}ms")
            }
            sb.appendLine()
            sb.appendLine("--- 最近日志 (tail) ---")
            sb.appendLine(viewModel.getLogTail(160))
            val clipboard = requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("diag", sb.toString()))
            Toast.makeText(requireContext(), "诊断结果已复制", Toast.LENGTH_SHORT).show()
        }

        viewModel.state.observe(viewLifecycleOwner) { state ->
            // Progress bar
            if (state.diagBusy) {
                binding.diagProgress.visibility = View.VISIBLE
                binding.diagProgress.progress = state.diagProgress
                binding.tvDiagStatus.text = state.diagProgressMsg
                binding.btnRunDiag.isEnabled = false
            } else {
                binding.diagProgress.visibility = View.INVISIBLE
                binding.tvDiagStatus.text = if (state.natType == "--") "点击开始检测" else "上次结果: ${state.natType}"
                binding.btnRunDiag.isEnabled = true
            }

            binding.tvNatType.text = state.natType
            binding.tvMappingBehavior.text = state.mappingBehavior
            binding.tvFilteringBehavior.text = state.filteringBehavior
            binding.tvPortPattern.text = state.portPattern
            binding.tvConfidence.text = state.confidence
            binding.tvPublicAddr.text = state.publicAddress
            binding.tvUpnp.text = state.upnpStatus
            binding.tvIpv6.text = state.ipv6Status
            binding.tvNetPriority.text = state.networkPriority

            stunAdapter.setData(state.stunMappings)
        }

        viewModel.logs.observe(viewLifecycleOwner) { logs ->
            logAdapter.setData(logs)
            if (logs.isNotEmpty()) {
                binding.rvLogs.scrollToPosition(logs.size - 1)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ──────────────────────────────────────────────
    // Adapters
    // ──────────────────────────────────────────────

    inner class StunMappingsAdapter : RecyclerView.Adapter<StunMappingsAdapter.VH>() {
        private var items: List<StunMapping> = emptyList()

        fun setData(data: List<StunMapping>) {
            items = data
            notifyDataSetChanged()
        }

        inner class VH(val binding: ItemStunMappingBinding) : RecyclerView.ViewHolder(binding.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(ItemStunMappingBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.binding.tvStunServer.text = item.server
            holder.binding.tvStunMapping.text = item.mapping
            holder.binding.tvStunRtt.text = "${item.rttMs}ms"
        }

        override fun getItemCount() = items.size
    }

    inner class LogAdapter : RecyclerView.Adapter<LogAdapter.VH>() {
        private var items: List<LogEntry> = emptyList()

        fun setData(data: List<LogEntry>) {
            items = data
            notifyDataSetChanged()
        }

        inner class VH(val binding: ItemLogBinding) : RecyclerView.ViewHolder(binding.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(ItemLogBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.binding.tvLogTime.text = item.time
            holder.binding.tvLogLevel.text = item.level
            holder.binding.tvLogLevel.setTextColor(when (item.level) {
                "ERROR" -> Color.parseColor("#FF4757")
                "WARN"  -> Color.parseColor("#FFA502")
                "INFO"  -> Color.parseColor("#00D4AA")
                else    -> Color.parseColor("#626880")
            })
            holder.binding.tvLogText.text = item.text
        }

        override fun getItemCount() = items.size
    }
}

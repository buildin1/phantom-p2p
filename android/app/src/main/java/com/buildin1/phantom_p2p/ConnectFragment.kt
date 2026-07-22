package com.buildin1.phantom_p2p

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.buildin1.phantom_p2p.databinding.FragmentConnectBinding

class ConnectFragment : Fragment() {

    private var _binding: FragmentConnectBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentConnectBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnDisconnect.setOnClickListener {
            val state = viewModel.state.value ?: return@setOnClickListener
            if (state.isHost) viewModel.closeRoom() else viewModel.leaveRoom()
        }

        binding.btnCopyAddr.setOnClickListener {
            val addr = viewModel.state.value?.guestAddr ?: return@setOnClickListener
            val clipboard = requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("guest_addr", addr))
            Toast.makeText(requireContext(), "地址已复制", Toast.LENGTH_SHORT).show()
        }

        viewModel.state.observe(viewLifecycleOwner) { state ->
            runCatching {
                renderState(state)
            }.onFailure { error ->
                Log.e(TAG, "render connect state failed: ${error.message}", error)
            }
        }
    }

    private fun renderState(state: AppState) {
        val binding = _binding ?: return
            val isActive = state.hostActive || state.guestActive
            binding.emptyState.visibility = if (isActive) View.GONE else View.VISIBLE
            binding.connectionCard.visibility = if (isActive) View.VISIBLE else View.GONE

            if (isActive) {
                // Connection mode badge
                binding.tvConnMode.text = state.connectionMode.ifBlank { "连接中" }

                // Latency
                if (state.latencyMs > 0) {
                    binding.tvLatency.text = state.latencyMs.toString()
                } else {
                    binding.tvLatency.text = "--"
                }

                // Upload / Download
                binding.tvUpload.text = formatBps(state.uploadBps)
                binding.tvDownload.text = formatBps(state.downloadBps)
                binding.tvUptime.text = formatUptime(state.uptimeSeconds)

                // Session IDs for topology
                val shortSelf = state.sessionId?.take(8) ?: "-------"
                val shortPeer = state.peerSessionId?.take(8) ?: "-------"
                binding.tvSelfId.text = shortSelf
                binding.tvPeerId.text = shortPeer
                binding.tvLinkLabel.text = state.connectionMode.ifBlank { "---" }
                binding.signalMapCard.visibility = View.VISIBLE

                // Guest address (only for guests)
                if (!state.isHost && state.guestAddr.isNotBlank() && !state.guestAddr.contains("----")) {
                    binding.guestAddrCard.visibility = View.VISIBLE
                    binding.tvGuestAddr.text = state.guestAddr
                } else {
                    binding.guestAddrCard.visibility = View.GONE
                }

                // Port forward panel (advanced mode)
                if (state.isAdvancedMode && state.portTunnelStatus.isNotEmpty()) {
                    binding.portForwardPanel.visibility = View.VISIBLE
                    renderPortForwardList(state)
                } else {
                    binding.portForwardPanel.visibility = View.GONE
                }
            } else {
                binding.signalMapCard.visibility = View.GONE
                binding.guestAddrCard.visibility = View.GONE
                binding.portForwardPanel.visibility = View.GONE
            }
    }

    private fun renderPortForwardList(state: AppState) {
        val container = binding.portForwardList
        container.removeAllViews()
        state.portTunnelStatus.forEach { (port, status) ->
            val tv = TextView(requireContext()).apply {
                text = "端口 $port  →  127.0.0.1:$port  " +
                        if (status == PortStatus.READY) "● 就绪" else "○ 等待中"
                textSize = 13f
                setPadding(12, 8, 12, 8)
                setTextColor(ContextCompat.getColor(
                    requireContext(),
                    if (status == PortStatus.READY) R.color.colorOk else R.color.textMuted
                ))
                typeface = android.graphics.Typeface.MONOSPACE
            }
            container.addView(tv)
        }
    }

    private fun formatBps(bps: Long): String {
        if (bps <= 0) return "-- KB/s"
        return if (bps < 1024 * 1024) "${bps / 1024} KB/s" else "${"%.1f".format(bps / 1024.0 / 1024.0)} MB/s"
    }

    private fun formatUptime(secs: Long): String {
        val h = secs / 3600
        val m = (secs % 3600) / 60
        val s = secs % 60
        return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%02d:%02d".format(m, s)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private companion object {
        const val TAG = "ConnectFragment"
    }
}

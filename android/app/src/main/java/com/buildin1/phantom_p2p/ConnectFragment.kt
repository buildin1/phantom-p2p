package com.buildin1.phantom_p2p

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.buildin1.phantom_p2p.databinding.FragmentConnectBinding

class ConnectFragment : Fragment() {

    private var _binding: FragmentConnectBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
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
            val clipboard = requireContext().getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("host_virtual_ip", addr))
            Toast.makeText(requireContext(), "地址已复制", Toast.LENGTH_SHORT).show()
        }

        viewModel.state.observe(viewLifecycleOwner) { state ->
            runCatching { renderState(state) }
                .onFailure { Log.e(TAG, "render connect state failed", it) }
        }
    }

    private fun renderState(state: AppState) {
        val binding = _binding ?: return
        val isActive = state.hostActive || state.guestActive
        binding.emptyState.visibility = if (isActive) View.GONE else View.VISIBLE
        binding.connectionCard.visibility = if (isActive) View.VISIBLE else View.GONE
        binding.portForwardPanel.visibility = View.GONE

        if (!isActive) {
            binding.signalMapCard.visibility = View.GONE
            binding.guestAddrCard.visibility = View.GONE
            return
        }

        val mode = state.connectionMode.ifBlank { "连接中" }
        binding.tvConnMode.text = mode
        binding.tvLatency.text = if (state.latencyMs > 0) state.latencyMs.toString() else "--"
        binding.tvUpload.text = formatBps(state.uploadBps)
        binding.tvDownload.text = formatBps(state.downloadBps)
        binding.tvUptime.text = formatUptime(state.uptimeSeconds)
        binding.tvSelfId.text = state.sessionId?.take(8) ?: "-------"
        binding.tvPeerId.text = state.peerSessionId?.take(8) ?: "-------"
        binding.tvLinkLabel.text = mode
        binding.signalMapCard.visibility = View.VISIBLE

        val showHostAddress = !state.isHost &&
            state.guestAddr.isNotBlank() &&
            !state.guestAddr.contains("--")
        binding.guestAddrCard.visibility = if (showHostAddress) View.VISIBLE else View.GONE
        if (showHostAddress) binding.tvGuestAddr.text = state.guestAddr
    }

    private fun formatBps(bps: Long): String {
        if (bps <= 0) return "-- KB/s"
        return if (bps < 1024 * 1024) {
            "${bps / 1024} KB/s"
        } else {
            "${"%.1f".format(bps / 1024.0 / 1024.0)} MB/s"
        }
    }

    private fun formatUptime(secs: Long): String {
        val hours = secs / 3600
        val minutes = (secs % 3600) / 60
        val seconds = secs % 60
        return if (hours > 0) {
            "%d:%02d:%02d".format(hours, minutes, seconds)
        } else {
            "%02d:%02d".format(minutes, seconds)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private companion object {
        const val TAG = "ConnectFragment"
    }
}

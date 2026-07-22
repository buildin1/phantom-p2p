package com.buildin1.phantom_p2p

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.buildin1.phantom_p2p.BuildConfig
import com.buildin1.phantom_p2p.databinding.FragmentSettingsBinding
import com.buildin1.phantom_p2p.signal.RoomTransport

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: AppViewModel by activityViewModels()

    private var selectedProto = RoomTransport.TCP
    private var startVpnAfterNotificationGrant = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        refreshRuntimeStatus()
        if (result.resultCode == Activity.RESULT_OK && VpnService.prepare(requireContext()) == null) {
            Toast.makeText(requireContext(), "VPN 权限已授权", Toast.LENGTH_SHORT).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        refreshRuntimeStatus()
        if (granted && startVpnAfterNotificationGrant) {
            startVpnAfterNotificationGrant = false
            startVpnService()
        } else if (!granted && startVpnAfterNotificationGrant) {
            startVpnAfterNotificationGrant = false
            Toast.makeText(requireContext(), "需要通知权限才能保持 VPN 前台常驻", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setupProtoSegment()
        setupRuntimeControls()

        // 开发者选项：仅 dev flavor 显示（服务器地址、联机配置、连接策略开关）
        binding.devSection.visibility =
            if (BuildConfig.FLAVOR == "dev") View.VISIBLE else View.GONE

        binding.btnSaveSettings.setOnClickListener {
            saveSettings()
        }

        binding.btnResetSettings.setOnClickListener {
            viewModel.resetSettings()
            Toast.makeText(requireContext(), "已恢复默认设置", Toast.LENGTH_SHORT).show()
        }

        viewModel.settings.observe(viewLifecycleOwner) { settings ->
            // Signal URL — show locked for user-mode
            binding.etSignalUrl.setText(settings.signal)
            binding.etSignalUrl.isEnabled = false

            binding.etGamePort.setText(settings.gamePort.toString())
            binding.etGuestPort.setText(settings.guestPort.toString())
            binding.switchAutoConnect.isChecked = settings.autoConnect
            binding.switchAutoRelay.isChecked = settings.autoRelay
            binding.switchRelayFallback.isChecked = settings.relayFallback
            binding.switchForceRelay.isChecked = settings.forceRelay
            binding.switchPreferIpv6.isChecked = settings.preferIpv6

            selectedProto = if (BuildConfig.FLAVOR == "dev" && settings.preferUdp) RoomTransport.UDP else RoomTransport.TCP
            updateProtoSegment(selectedProto)
        }

        refreshRuntimeStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshRuntimeStatus()
    }

    private fun setupProtoSegment() {
        binding.btnProtoTcp.setOnClickListener {
            selectedProto = RoomTransport.TCP
            updateProtoSegment(RoomTransport.TCP)
        }
        binding.btnProtoUdp.setOnClickListener {
            selectedProto = RoomTransport.UDP
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

    private fun setupRuntimeControls() {
        binding.btnGrantVpnPermission.setOnClickListener {
            requestVpnPermission()
        }
        binding.btnGrantBackgroundPermission.setOnClickListener {
            requestBackgroundKeepAlive()
        }
        binding.btnStartVpnService.setOnClickListener {
            startVpnService()
        }
        binding.btnStopVpnService.setOnClickListener {
            PhantomVpnService.stop(requireContext())
            refreshRuntimeStatus()
            Toast.makeText(requireContext(), "VPN 服务已停止", Toast.LENGTH_SHORT).show()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(requireContext())
        if (intent == null) {
            refreshRuntimeStatus()
            Toast.makeText(requireContext(), "VPN 权限已授权", Toast.LENGTH_SHORT).show()
            return
        }
        vpnPermissionLauncher.launch(intent)
    }

    private fun requestBackgroundKeepAlive() {
        val context = requireContext()
        val powerManager = context.getSystemService(PowerManager::class.java)
        if (powerManager != null && powerManager.isIgnoringBatteryOptimizations(context.packageName)) {
            refreshRuntimeStatus()
            Toast.makeText(context, "后台白名单已开启", Toast.LENGTH_SHORT).show()
            return
        }

        val packageUri = Uri.parse("package:${context.packageName}")
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, packageUri)
        if (intent.resolveActivity(context.packageManager) != null) {
            startActivity(intent)
        } else {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }

    private fun startVpnService() {
        val context = requireContext()
        if (VpnService.prepare(context) != null) {
            Toast.makeText(context, "请先授权 VPN 权限", Toast.LENGTH_SHORT).show()
            requestVpnPermission()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            startVpnAfterNotificationGrant = true
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }

        PhantomVpnService.start(context)
        refreshRuntimeStatus()
        Toast.makeText(context, "VPN 服务已启动", Toast.LENGTH_SHORT).show()
    }

    private fun refreshRuntimeStatus() {
        val context = requireContext()
        val vpnGranted = VpnService.prepare(context) == null
        val powerManager = context.getSystemService(PowerManager::class.java)
        val backgroundAllowed = powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
        val running = PhantomVpnService.isRunning(context)

        binding.tvVpnPermissionStatus.text = getString(
            if (vpnGranted) R.string.status_granted else R.string.status_not_granted
        )
        binding.tvBackgroundPermissionStatus.text = getString(
            if (backgroundAllowed) R.string.status_whitelisted else R.string.status_not_whitelisted
        )
        binding.tvVpnRuntimeStatus.text = getString(
            if (running) R.string.status_running else R.string.status_stopped
        )

        binding.btnGrantVpnPermission.isEnabled = !vpnGranted
        binding.btnGrantBackgroundPermission.isEnabled = !backgroundAllowed
        binding.btnStartVpnService.isEnabled = vpnGranted && !running
        binding.btnStopVpnService.isEnabled = running
    }

    private fun saveSettings() {
        val gamePort = binding.etGamePort.text.toString().toIntOrNull() ?: 25565
        val guestPort = binding.etGuestPort.text.toString().toIntOrNull() ?: 25642
        val s = AppSettings(
            signal = USER_MODE_LOCKED_SIGNAL,
            gamePort = gamePort,
            guestPort = guestPort,
            preferUdp = BuildConfig.FLAVOR == "dev" && selectedProto == RoomTransport.UDP,
            relayFallback = binding.switchRelayFallback.isChecked,
            forceRelay = binding.switchForceRelay.isChecked,
            autoRelay = binding.switchAutoRelay.isChecked,
            autoConnect = binding.switchAutoConnect.isChecked,
            preferIpv6 = binding.switchPreferIpv6.isChecked,
            verbose = false
        )
        viewModel.saveSettings(s)
        Toast.makeText(requireContext(), "设置已保存", Toast.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

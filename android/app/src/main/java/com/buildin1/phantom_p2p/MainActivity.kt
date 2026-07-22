package com.buildin1.phantom_p2p

import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams
import androidx.fragment.app.Fragment
import com.buildin1.phantom_p2p.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val vm: AppViewModel by viewModels()
    private var selectedTabId: Int = R.id.nav_room

    /** VPN 授权对话框回调：结果封装回 ViewModel */
    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) vm.onVpnGranted()
        else vm.onVpnDenied()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val dp8  = (8  * resources.displayMetrics.density).toInt()
        val dp12 = (12 * resources.displayMetrics.density).toInt()

        ViewCompat.setOnApplyWindowInsetsListener(binding.rootLayout) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            // Push topBar below the status bar
            binding.topBar.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                topMargin = bars.top + dp8
            }
            // Push bottomNavShell above the nav bar
            binding.bottomNavShell.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                bottomMargin = bars.bottom + dp12
            }
            insets
        }
        ViewCompat.requestApplyInsets(binding.rootLayout)

        selectedTabId = savedInstanceState?.getInt(KEY_SELECTED_TAB) ?: R.id.nav_room

        binding.navRoomItem.setOnClickListener { selectTab(R.id.nav_room) }
        binding.navConnectItem.setOnClickListener { selectTab(R.id.nav_connect) }
        binding.navDiagItem.setOnClickListener { selectTab(R.id.nav_diag) }
        binding.navSettingsItem.setOnClickListener { selectTab(R.id.nav_settings) }

        if (savedInstanceState == null) {
            selectTab(selectedTabId, forceSwitch = true)
        } else {
            updateBottomNavSelection(selectedTabId)
        }

        // 开启自动连接信令（无需 VPN）
        if (vm.settings.value?.autoConnect != false) vm.ensureConnected()

        // 申请电池优化豆免（仅在未豆免时弹一次）
        requestBatteryOptimizationExemption()

        // 观察 ViewModel 发出的 VPN 授权请求（创建/加入房间时触发）
        vm.vpnPermissionNeeded.observe(this) { vpnIntent ->
            if (vpnIntent != null) vpnPermLauncher.launch(vpnIntent)
        }

        // 连接成功后跳转到连接页
        vm.navigateToTab.observe(this) { tabId ->
            if (tabId != null) {
                selectTab(tabId)
                vm.clearNavigateToTab()
            }
        }

        vm.state.observe(this) { state ->
            binding.tvTopSubtitle.text = when (state.connectionState) {
                ConnectionState.DISCONNECTED -> getString(R.string.status_offline)
                ConnectionState.CONNECTING -> getString(R.string.status_connecting)
                ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED ->
                    state.userId?.let { "已连接 · $it" } ?: getString(R.string.status_online)
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt(KEY_SELECTED_TAB, selectedTabId)
        super.onSaveInstanceState(outState)
    }
    /** 申请电池优化豁免：后台不被系统杀死（仅在未豁免时弹一次） */
    private fun requestBatteryOptimizationExemption() {
        val pm = getSystemService(PowerManager::class.java)
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            runCatching {
                startActivity(
                    android.content.Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:$packageName")
                    )
                )
            }
        }
    }

    private fun selectTab(itemId: Int, forceSwitch: Boolean = false) {
        if (!forceSwitch && itemId == selectedTabId) {
            return
        }

        selectedTabId = itemId
        updateBottomNavSelection(itemId)
        switchFragment(fragmentFor(itemId))
    }

    private fun updateBottomNavSelection(itemId: Int) {
        binding.navRoomItem.isSelected = itemId == R.id.nav_room
        binding.navConnectItem.isSelected = itemId == R.id.nav_connect
        binding.navDiagItem.isSelected = itemId == R.id.nav_diag
        binding.navSettingsItem.isSelected = itemId == R.id.nav_settings
    }

    private fun fragmentFor(itemId: Int): Fragment = when (itemId) {
        R.id.nav_room -> RoomFragment()
        R.id.nav_connect -> ConnectFragment()
        R.id.nav_diag -> DiagFragment()
        R.id.nav_settings -> SettingsFragment()
        else -> RoomFragment()
    }

    private fun switchFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .setReorderingAllowed(true)
            .setCustomAnimations(
                R.anim.fragment_fade_in,
                R.anim.fragment_fade_out,
                R.anim.fragment_fade_in,
                R.anim.fragment_fade_out
            )
            .replace(R.id.fragmentContainer, fragment)
            .commit()
    }

    private companion object {
        const val KEY_SELECTED_TAB = "selected_tab"
    }
}


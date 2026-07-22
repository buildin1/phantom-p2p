package com.buildin1.phantom_p2p

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * 开机 / 包更新后自动拉起 VPN 前台服务（保持后台保活）。
 * 仅在用户之前已授权 VPN 时才启动（VpnService.prepare 返回 null 表示已授权）。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) return

        // Android 15+ 对 BOOT_COMPLETED 拉起前台服务更严格；这里仅保留授权检查，
        // 真正的数据面由用户进入房间后通过 attachP2P/attachRelay 启动。
        VpnService.prepare(context)
    }
}

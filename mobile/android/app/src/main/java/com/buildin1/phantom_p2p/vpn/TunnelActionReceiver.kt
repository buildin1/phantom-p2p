package com.buildin1.phantom_p2p.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * 通知栏快捷操作的落点。
 *
 * 断开走 [PhantomVpnService.ACTION_DISCONNECT]（服务自己处理），
 * 重连需要先确认 VPN 授权仍然有效，所以要把用户拉回应用——
 * 从广播里直接 startForegroundService 在授权已被撤销时会静默失败。
 */
class TunnelActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            PhantomVpnService.ACTION_DISCONNECT -> {
                context.startService(
                    Intent(context, PhantomVpnService::class.java)
                        .setAction(PhantomVpnService.ACTION_DISCONNECT)
                )
            }

            PhantomVpnService.ACTION_RECONNECT -> {
                val launch = context.packageManager
                    .getLaunchIntentForPackage(context.packageName)
                    ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                launch?.let(context::startActivity)
            }
        }
    }
}

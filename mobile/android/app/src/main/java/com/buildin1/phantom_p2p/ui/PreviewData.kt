package com.buildin1.phantom_p2p.ui

import com.buildin1.phantom_p2p.engine.LinkStats
import com.buildin1.phantom_p2p.engine.NatClass
import com.buildin1.phantom_p2p.engine.NetworkDiagnostics
import com.buildin1.phantom_p2p.engine.NetworkProfile
import com.buildin1.phantom_p2p.engine.StunDetail

/**
 * `@Preview` 用的静态样本。
 *
 * 这里只有数据，没有行为 —— 之前那个会按真实时序演一遍完整连接流程的
 * 假引擎已经删掉了，它在接上真引擎之后就只是打进 APK 的死重。
 *
 * 预览本身保留：整套设计体系是围绕它建起来的，没有预览就只能靠装机看效果。
 */
object PreviewData {

    val stats = LinkStats(
        latencyMillis = 12,
        lossPercent = 0.3,
        upMbps = 1.2,
        downMbps = 3.4,
        latencyHistory = listOf(
            14, 13, 15, 12, 14, 11, 13, 10, 14, 12,
            15, 11, 13, 10, 12, 11, 14, 10, 12, 9,
            13, 11, 12, 10, 13, 12, 11, 13, 10, 12,
        ),
    )

    val profile = NetworkProfile(
        natClass = NatClass.PortRestrictedCone,
        mappingStable = true,
        ipv6Available = true,
        mtu = 1160,
    )

    val diagnostics = NetworkDiagnostics(
        natType = "端口受限锥型",
        natTypeKey = "port_restricted_cone",
        natDifficulty = "中等 · 需要同步打洞",
        externalIp = "113.87.64.21",
        externalPort = 51820,
        upnp = false,
        upnpPort = 0,
        ipv6 = true,
        ipv6Addr = "2409:8a55:1b2c::9f1",
        localIp = "192.168.1.37",
        localPort = 51820,
        stunDetails = listOf(
            StunDetail("stun.dcalling.de", "113.87.64.21:51820", 38, "A", 1),
            StunDetail("stun.skydrone.aero", "113.87.64.21:51820", 52, "A", 1),
            StunDetail("stun.dcalling.de", "113.87.64.21:51821", 41, "B", 1),
        ),
        portPattern = "端口一致",
        mappingBehavior = "端点无关映射",
        filteringBehavior = "地址与端口限制",
        confidence = "高",
        rounds = 3,
        networkPriority = "ipv6",
        mtu = 1160,
    )
}

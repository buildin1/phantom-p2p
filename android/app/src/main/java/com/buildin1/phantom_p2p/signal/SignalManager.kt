package com.buildin1.phantom_p2p.signal

import android.util.Log
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.msgpack.jackson.dataformat.MessagePackMapper
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.util.concurrent.TimeUnit

private const val TAG = "SignalManager"
private const val PING_INTERVAL_MS = 10_000L  // 应用层心跳间隔，必须小于服务器 20s 超时

/**
 * WebSocket 信令客户端。
 *
 * 使用 MessagePack 序列化（与桌面端和服务端一致）。
 * 连接后自动进行 Ed25519 鉴权，鉴权完成后触发 [onAuthenticated]。
 */
class SignalManager(
    private val identity: IdentityManager,
    private val listener: SignalListener
) {
    interface SignalListener {
        fun onConnected(sessionId: String)
        fun onAuthenticated(userId: String)
        fun onAuthFailed(reason: String)
        fun onRoomCreated(roomCode: String, subnet: String, virtualIp: String)
        fun onJoinOk(roomCode: String, hostSessionId: String, subnet: String, virtualIp: String, hostVirtualIp: String)
        fun onJoinFailed(reason: String)
        fun onPeerJoined(peerSessionId: String, guestCount: Int)
        fun onPeerLeft(peerSessionId: String, guestCount: Int)
        fun onRoomClosed(reason: String)
        fun onPeerCandidates(msg: ServerMessage.PeerCandidates)
        fun onRelayPreAllocated(msg: ServerMessage.RelayPreAllocated)
        fun onRelayReady(msg: ServerMessage.RelayReady)
        fun onError(message: String)
        fun onDisconnected(code: Int, reason: String)
        fun onLog(message: String)
        fun onFixedHostIpStatus(enabled: Boolean, virtualIp: String?)
    }

    private val mapper: ObjectMapper = MessagePackMapper()
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
        .findAndRegisterModules()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .build()

    private var ws: WebSocket? = null
    private var pingJob: Job? = null
    var isConnected: Boolean = false
        private set
    var isAuthenticated: Boolean = false
        private set

    fun connect(url: String) {
        val wsUrl = if (!url.startsWith("ws")) "ws://$url" else url
        val request = Request.Builder().url(wsUrl).build()
        Log.i(TAG, "Connecting to $wsUrl")
        scope.launch {
            runCatching { preflight(wsUrl) }
                .onFailure { err ->
                    listener.onLog("⚠️ 连接预检失败: ${err.message}")
                }
        }
        ws = client.newWebSocket(request, WsListener())
    }

    fun disconnect() {
        ws?.close(1000, "user disconnect")
        ws = null
    }

    fun send(msg: ClientMessage) {
        val bytes = mapper.writeValueAsBytes(msg)
        runCatching {
            val debug = mapper.writeValueAsString(msg)
            listener.onLog("TX: $debug")
        }
        ws?.send(ByteString.of(*bytes))
    }

    fun createRoom() = send(ClientMessage.CreateRoom)
    fun hostReady() = send(ClientMessage.HostReady)

    fun joinRoom(roomCode: String) {
        send(ClientMessage.JoinRoom(roomCode))
    }

    fun closeRoom() {
        send(ClientMessage.CloseRoom)
    }

    fun leaveRoom() {
        send(ClientMessage.LeaveRoom)
    }

    fun requestFixedHostIp() = send(ClientMessage.RequestFixedHostIp)
    fun releaseFixedHostIp() = send(ClientMessage.ReleaseFixedHostIp)
    fun getFixedHostIp() = send(ClientMessage.GetFixedHostIp)

    fun sendIceCandidates(candidates: List<IceCandidate>, ufrag: String, pwd: String, natType: String) {
        send(ClientMessage.IceCandidates(candidates, ufrag, pwd, natType))
    }

    fun requestRelay() {
        send(ClientMessage.RelayRequest)
    }

    fun destroy() {
        disconnect()
        scope.cancel()
        client.dispatcher.executorService.shutdown()
    }

    // ── WebSocket listener ──

    private inner class WsListener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            isConnected = true
            isAuthenticated = false
            Log.i(TAG, "WebSocket opened")
            // 启动应用层心跳：每 10s 发一次 MessagePack Ping，服务器据此更新 last_activity
            pingJob = scope.launch {
                while (true) {
                    delay(PING_INTERVAL_MS)
                    if (!isConnected) break
                    val bytes = mapper.writeValueAsBytes(ClientMessage.Ping)
                    webSocket.send(ByteString.of(*bytes))
                }
            }
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            scope.launch {
                try {
                    val msg = mapper.readValue(bytes.toByteArray(), ServerMessage::class.java)
                    handleMessage(webSocket, msg)
                } catch (e: Exception) {
                    Log.e(TAG, "消息解码失败: ${e::class.simpleName}: ${e.message}", e)
                    listener.onLog("⚠️ 消息解码失败: ${e::class.simpleName}: ${e.message}")
                }
            }
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            // server sends binary only; ignore text frames
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            pingJob?.cancel(); pingJob = null
            isConnected = false
            isAuthenticated = false
            webSocket.close(code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            pingJob?.cancel(); pingJob = null
            isConnected = false
            isAuthenticated = false
            listener.onDisconnected(code, reason)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            pingJob?.cancel(); pingJob = null
            isConnected = false
            isAuthenticated = false
            val httpCode = response?.code
            val root = t.message ?: "未知错误"
            val hint = when {
                root.contains("CLEARTEXT", ignoreCase = true) -> "；请检查 cleartext 策略是否放行 ws 域名"
                root.contains("Unable to resolve host", ignoreCase = true) -> "；DNS 解析失败（手机网络/运营商）"
                root.contains("timeout", ignoreCase = true) -> "；连接超时（端口不可达或网络拦截）"
                else -> ""
            }
            val reason = (if (httpCode != null) "$root (http=$httpCode)" else root) + hint
            Log.e(TAG, "WebSocket failure: $reason", t)
            listener.onLog("⚠️ 信令连接失败: $reason")
            listener.onDisconnected(-1, reason)
        }
    }

    private fun preflight(wsUrl: String) {
        val uri = URI(wsUrl)
        val host = uri.host ?: throw IllegalArgumentException("无效信令地址: host 为空")
        val port = when {
            uri.port > 0 -> uri.port
            uri.scheme.equals("wss", ignoreCase = true) -> 443
            else -> 80
        }

        val resolved = runCatching { java.net.InetAddress.getAllByName(host).toList() }
            .getOrElse { throw IllegalStateException("DNS 解析失败: ${it.message}") }

        val firstIp = resolved.firstOrNull()?.hostAddress ?: "?"
        listener.onLog("信令预检: $host:$port -> $firstIp")

        val tcpOk = runCatching {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 2500)
            }
        }.isSuccess

        if (!tcpOk) {
            throw IllegalStateException("TCP 端口不可达: $host:$port")
        }
    }

    private fun handleMessage(webSocket: WebSocket, msg: ServerMessage) {
        when (msg) {
            is ServerMessage.Welcome -> {
                listener.onConnected(msg.sessionId)
                listener.onLog("信令已连接，session ${msg.sessionId}")
            }

            is ServerMessage.AuthChallenge -> {
                try {
                    Log.i(TAG, "收到 AuthChallenge nonce[${msg.nonce.size}bytes]")
                    val sig = identity.sign(msg.nonce)
                    val authMsg = ClientMessage.Auth(identity.publicKeyBytes, sig)
                    val bytes = mapper.writeValueAsBytes(authMsg)
                    val sent = webSocket.send(ByteString.of(*bytes))
                    val logMsg = if (sent) "鉴权响应已发送 (${identity.userId()})" else "⚠️ 鉴权响应入队失败"
                    listener.onLog(logMsg)
                    Log.i(TAG, "Auth sent=$sent pubkey=${identity.userId()}")
                } catch (e: Exception) {
                    Log.e(TAG, "Auth 发送异常: ${e::class.simpleName}: ${e.message}", e)
                    listener.onLog("⚠️ 鉴权异常: ${e::class.simpleName}: ${e.message}")
                }
            }

            is ServerMessage.AuthOk -> {
                isAuthenticated = true
                listener.onAuthenticated(msg.userId)
                listener.onLog("鉴权成功 user_id=${msg.userId}")
            }

            is ServerMessage.AuthFailed -> {
                listener.onAuthFailed(msg.reason)
                listener.onLog("⚠️ 鉴权失败: ${msg.reason}")
            }

            is ServerMessage.RoomCreated -> {
                listener.onRoomCreated(msg.roomCode, msg.subnet, msg.virtualIp)
                listener.onLog("房间已创建，房间码 ${msg.roomCode}")
            }

            is ServerMessage.JoinOk -> {
                listener.onJoinOk(msg.roomCode, msg.hostSessionId, msg.subnet, msg.virtualIp, msg.hostVirtualIp)
                listener.onLog("加入房间成功，虚拟地址 ${msg.virtualIp}")
            }

            is ServerMessage.JoinFailed -> {
                listener.onJoinFailed(msg.reason)
                listener.onLog("⚠️ 加入房间失败: ${msg.reason}")
            }

            is ServerMessage.PeerJoined -> {
                listener.onPeerJoined(msg.peerSessionId, msg.guestCount)
                listener.onLog("玩家加入 ${msg.peerSessionId}（共 ${msg.guestCount} 人）")
            }

            is ServerMessage.PeerLeft -> {
                listener.onPeerLeft(msg.peerSessionId, msg.guestCount)
                listener.onLog("玩家离开 ${msg.peerSessionId}（剩余 ${msg.guestCount} 人）")
            }

            is ServerMessage.RoomClosed -> {
                listener.onRoomClosed(msg.reason)
                listener.onLog("房间已关闭: ${msg.reason}")
            }

            is ServerMessage.PeerCandidates -> {
                listener.onPeerCandidates(msg)
                listener.onLog("收到 PeerCandidates，开始连通性检测")
            }

            is ServerMessage.FixedHostIpStatus -> {
                listener.onFixedHostIpStatus(msg.enabled, msg.virtualIp)
            }

            is ServerMessage.RelayPreAllocated -> {
                listener.onRelayPreAllocated(msg)
                listener.onLog("QUIC 通道已预分配 ${msg.relayAddr}:${msg.relayQuicPort}")
            }

            is ServerMessage.RelayReady -> {
                listener.onRelayReady(msg)
                listener.onLog("中继就绪 ${msg.relayAddr}")
            }

            is ServerMessage.Error -> {
                listener.onError(msg.message)
                listener.onLog("⚠️ 服务器错误: ${msg.message}")
            }

            is ServerMessage.Pong -> { /* 心跳，忽略 */ }

        }
    }
}

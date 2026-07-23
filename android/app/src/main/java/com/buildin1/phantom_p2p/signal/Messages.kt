package com.buildin1.phantom_p2p.signal

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo

data class IceCandidate(
    @JsonProperty("ip") val ip: String,
    @JsonProperty("port") val port: Int,
    @JsonProperty("ctype") val ctype: String,
    @JsonProperty("priority") val priority: Long,
    @JsonProperty("foundation") val foundation: String
)

// Kept only for migrating legacy settings; it is no longer serialized in room messages.
enum class RoomTransport { TCP, UDP }

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "cmd")
@JsonSubTypes(
    JsonSubTypes.Type(ClientMessage.Ping::class, name = "ping"),
    JsonSubTypes.Type(ClientMessage.Auth::class, name = "auth"),
    JsonSubTypes.Type(ClientMessage.CreateRoom::class, name = "create_room"),
    JsonSubTypes.Type(ClientMessage.HostReady::class, name = "host_ready"),
    JsonSubTypes.Type(ClientMessage.JoinRoom::class, name = "join_room"),
    JsonSubTypes.Type(ClientMessage.LeaveRoom::class, name = "leave_room"),
    JsonSubTypes.Type(ClientMessage.CloseRoom::class, name = "close_room"),
    JsonSubTypes.Type(ClientMessage.IceCandidates::class, name = "ice_candidates"),
    JsonSubTypes.Type(ClientMessage.RelayRequest::class, name = "relay_request"),
    JsonSubTypes.Type(ClientMessage.RelayUpgradeRequest::class, name = "relay_upgrade_request"),
    JsonSubTypes.Type(ClientMessage.RequestFixedHostIp::class, name = "request_fixed_host_ip"),
    JsonSubTypes.Type(ClientMessage.ReleaseFixedHostIp::class, name = "release_fixed_host_ip"),
    JsonSubTypes.Type(ClientMessage.GetFixedHostIp::class, name = "get_fixed_host_ip")
)
sealed class ClientMessage {
    object Ping : ClientMessage()

    data class Auth(
        @JsonProperty("public_key") val publicKey: ByteArray,
        @JsonProperty("signature") val signature: ByteArray
    ) : ClientMessage()

    object CreateRoom : ClientMessage()
    object HostReady : ClientMessage()
    data class JoinRoom(@JsonProperty("room_code") val roomCode: String) : ClientMessage()
    object LeaveRoom : ClientMessage()
    object CloseRoom : ClientMessage()
    object RelayRequest : ClientMessage()
    object RelayUpgradeRequest : ClientMessage()
    object RequestFixedHostIp : ClientMessage()
    object ReleaseFixedHostIp : ClientMessage()
    object GetFixedHostIp : ClientMessage()

    data class IceCandidates(
        @JsonProperty("candidates") val candidates: List<IceCandidate>,
        @JsonProperty("ufrag") val ufrag: String,
        @JsonProperty("pwd") val pwd: String,
        @JsonProperty("nat_type") val natType: String
    ) : ClientMessage()
}

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "cmd")
@JsonSubTypes(
    JsonSubTypes.Type(ServerMessage.Welcome::class, name = "welcome"),
    JsonSubTypes.Type(ServerMessage.Pong::class, name = "pong"),
    JsonSubTypes.Type(ServerMessage.AuthChallenge::class, name = "auth_challenge"),
    JsonSubTypes.Type(ServerMessage.AuthOk::class, name = "auth_ok"),
    JsonSubTypes.Type(ServerMessage.AuthFailed::class, name = "auth_failed"),
    JsonSubTypes.Type(ServerMessage.RoomCreated::class, name = "room_created"),
    JsonSubTypes.Type(ServerMessage.JoinOk::class, name = "join_ok"),
    JsonSubTypes.Type(ServerMessage.JoinFailed::class, name = "join_failed"),
    JsonSubTypes.Type(ServerMessage.PeerJoined::class, name = "peer_joined"),
    JsonSubTypes.Type(ServerMessage.PeerLeft::class, name = "peer_left"),
    JsonSubTypes.Type(ServerMessage.RoomClosed::class, name = "room_closed"),
    JsonSubTypes.Type(ServerMessage.PeerCandidates::class, name = "peer_candidates"),
    JsonSubTypes.Type(ServerMessage.RelayReady::class, name = "relay_ready"),
    JsonSubTypes.Type(ServerMessage.RelayPreAllocated::class, name = "relay_pre_allocated"),
    JsonSubTypes.Type(ServerMessage.FixedHostIpStatus::class, name = "fixed_host_ip_status"),
    JsonSubTypes.Type(ServerMessage.Error::class, name = "error")
)
sealed class ServerMessage {
    data class Welcome(@JsonProperty("session_id") val sessionId: String) : ServerMessage()
    object Pong : ServerMessage()
    data class AuthChallenge(@JsonProperty("nonce") val nonce: ByteArray) : ServerMessage()
    data class AuthOk(@JsonProperty("user_id") val userId: String) : ServerMessage()
    data class AuthFailed(@JsonProperty("reason") val reason: String) : ServerMessage()

    data class RoomCreated(
        @JsonProperty("room_code") val roomCode: String,
        @JsonProperty("subnet") val subnet: String,
        @JsonProperty("virtual_ip") val virtualIp: String
    ) : ServerMessage()

    data class JoinOk(
        @JsonProperty("room_code") val roomCode: String,
        @JsonProperty("host_session_id") val hostSessionId: String,
        @JsonProperty("subnet") val subnet: String,
        @JsonProperty("virtual_ip") val virtualIp: String,
        @JsonProperty("host_virtual_ip") val hostVirtualIp: String
    ) : ServerMessage()

    data class JoinFailed(@JsonProperty("reason") val reason: String) : ServerMessage()
    data class PeerJoined(
        @JsonProperty("peer_session_id") val peerSessionId: String,
        @JsonProperty("guest_count") val guestCount: Int
    ) : ServerMessage()
    data class PeerLeft(
        @JsonProperty("peer_session_id") val peerSessionId: String,
        @JsonProperty("guest_count") val guestCount: Int
    ) : ServerMessage()
    data class RoomClosed(@JsonProperty("reason") val reason: String) : ServerMessage()
    data class PeerCandidates(
        @JsonProperty("peer_session_id") val peerSessionId: String,
        @JsonProperty("candidates") val candidates: List<IceCandidate>,
        @JsonProperty("peer_ufrag") val peerUfrag: String,
        @JsonProperty("peer_pwd") val peerPwd: String,
        @JsonProperty("peer_nat_type") val peerNatType: String,
        @JsonProperty("start_at_ms") val startAtMs: Long
    ) : ServerMessage()
    data class RelayReady(
        @JsonProperty("room_code") val roomCode: String,
        @JsonProperty("relay_addr") val relayAddr: String,
        @JsonProperty("relay_quic_port") val relayQuicPort: Int,
        @JsonProperty("token") val token: String
    ) : ServerMessage()
    data class RelayPreAllocated(
        @JsonProperty("room_code") val roomCode: String,
        @JsonProperty("relay_addr") val relayAddr: String,
        @JsonProperty("relay_quic_port") val relayQuicPort: Int,
        @JsonProperty("token") val token: String
    ) : ServerMessage()
    data class FixedHostIpStatus(
        @JsonProperty("enabled") val enabled: Boolean,
        @JsonProperty("virtual_ip") val virtualIp: String?
    ) : ServerMessage()
    data class Error(@JsonProperty("message") val message: String) : ServerMessage()
}

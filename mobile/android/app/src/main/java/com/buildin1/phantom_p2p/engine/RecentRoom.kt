package com.buildin1.phantom_p2p.engine

/**
 * 记住过的房间。
 *
 * 移动端点名的需求：用户在手机上重复输六位码是最烦的一步。存在本机偏好里，
 * 与引擎无关，所以不进 [EngineClient]。
 *
 * [relativeHint] 是「昨天」「周二」这种已经算好的相对时间文案，不是时间戳——
 * 格式化属于展示层，让它在这里定型可以避免列表每次重组都重新算一遍。
 */
data class RecentRoom(
    val code: String,
    val relativeHint: String,
)

//! 端口池管理
//!
//! 为中继服务器和 Guest 客户端提供动态端口分配

use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

/// 端口池
pub struct PortPool {
    /// 可用端口列表
    available: Vec<u16>,
    /// 已分配的端口: session_id/token → port
    allocated: HashMap<String, u16>,
    /// 端口范围
    range: (u16, u16),
}

impl PortPool {
    /// 创建新的端口池
    pub fn new(start: u16, end: u16) -> Self {
        let available: Vec<u16> = (start..=end).collect();
        info!(
            "[端口池] 初始化端口池: {}-{} (共 {} 个端口)",
            start,
            end,
            available.len()
        );
        Self {
            available,
            allocated: HashMap::new(),
            range: (start, end),
        }
    }

    /// 分配一个端口
    pub fn allocate(&mut self, id: &str) -> Option<u16> {
        // 如果已经分配过,直接返回
        if let Some(&port) = self.allocated.get(id) {
            return Some(port);
        }

        // 从可用列表中取出一个端口
        let port = self.available.pop()?;
        self.allocated.insert(id.to_string(), port);
        info!("[端口池] 分配端口 {} 给 {}", port, id);
        Some(port)
    }

    /// 释放端口
    pub fn release(&mut self, id: &str) {
        if let Some(port) = self.allocated.remove(id) {
            self.available.push(port);
            info!("[端口池] 释放端口 {} (来自 {})", port, id);
        }
    }

    /// 获取可用端口数量
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// 获取已分配端口数量
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// 获取端口范围
    pub fn range(&self) -> (u16, u16) {
        self.range
    }
}

/// 中继端口池（单池，按房间协议动态分配）
pub struct RelayPortPool {
    /// 可用端口池
    available: Vec<u16>,
    /// 已分配端口：token → port
    allocated: HashMap<String, u16>,
}

impl RelayPortPool {
    /// 创建新的中继端口池
    pub fn new(start: u16, end: u16) -> Self {
        let available: Vec<u16> = (start..=end).collect();

        info!(
            "[中继端口池] 初始化单池: {}-{} ({} 个端口)",
            start,
            end,
            available.len()
        );

        Self {
            available,
            allocated: HashMap::new(),
        }
    }

    /// 分配一个中继端口
    pub fn allocate(&mut self, token: &str) -> Option<u16> {
        let excluded = HashSet::new();
        self.allocate_excluding(token, &excluded)
    }

    /// 分配一个中继端口，并排除指定端口集合
    pub fn allocate_excluding(&mut self, token: &str, excluded: &HashSet<u16>) -> Option<u16> {
        // 如果已经分配过,直接返回
        if let Some(&port) = self.allocated.get(token) {
            return Some(port);
        }

        // 从可用池中取一个不在排除集合中的端口
        let index = self
            .available
            .iter()
            .rposition(|port| !excluded.contains(port))?;
        let port = self.available.swap_remove(index);

        self.allocated.insert(token.to_string(), port);
        info!("[中继端口池] 分配端口 {} 给 token:{}", port, token);
        Some(port)
    }

    /// 从可用池中移除不可用端口（例如监听绑定失败）
    pub fn remove_port(&mut self, port: u16) -> bool {
        if let Some(idx) = self.available.iter().position(|p| *p == port) {
            self.available.swap_remove(idx);
            warn!("[中继端口池] 移除不可用端口: {}", port);
            return true;
        }
        false
    }

    /// 释放端口
    pub fn release(&mut self, token: &str) {
        if let Some(port) = self.allocated.remove(token) {
            self.available.push(port);
            info!("[中继端口池] 释放端口 {} (token:{})", port, token);
        }
    }

    /// 获取可用端口数量
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// 获取已分配端口数量
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// 获取指定 token 的端口
    pub fn get(&self, token: &str) -> Option<u16> {
        self.allocated.get(token).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_pool_basic() {
        let mut pool = PortPool::new(25600, 25610);

        // 分配端口
        let port1 = pool.allocate("session1").unwrap();
        assert_eq!(port1, 25610); // 从末尾取

        let port2 = pool.allocate("session2").unwrap();
        assert_eq!(port2, 25609);

        // 重复分配返回相同端口
        let port1_again = pool.allocate("session1").unwrap();
        assert_eq!(port1_again, port1);

        // 释放端口
        pool.release("session1");
        assert_eq!(pool.available_count(), 10);

        // 可以重新分配
        let port3 = pool.allocate("session3").unwrap();
        assert_eq!(port3, 25610); // 复用刚释放的
    }

    #[test]
    fn test_relay_port_pool_basic() {
        let mut pool = RelayPortPool::new(10113, 10118);

        // 分配端口
        let port1 = pool.allocate("token1").unwrap();
        assert_eq!(port1, 10118);

        let port2 = pool.allocate("token2").unwrap();
        assert_eq!(port2, 10117);

        // 重复分配返回相同端口
        let port1_again = pool.allocate("token1").unwrap();
        assert_eq!(port1_again, port1);

        // 释放端口
        pool.release("token1");
        assert_eq!(pool.available_count(), 5);

        // 可以重新分配
        let port3 = pool.allocate("token3").unwrap();
        assert_eq!(port3, 10118);
    }

    #[test]
    fn test_port_pool_exhaustion() {
        let mut pool = PortPool::new(25600, 25602); // 只有 3 个端口

        pool.allocate("s1").unwrap();
        pool.allocate("s2").unwrap();
        pool.allocate("s3").unwrap();

        // 端口耗尽
        assert!(pool.allocate("s4").is_none());
        assert_eq!(pool.available_count(), 0);

        // 释放后可以继续分配
        pool.release("s1");
        assert!(pool.allocate("s4").is_some());
    }
}

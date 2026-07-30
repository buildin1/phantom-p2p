//! 出口公网 IP / 宽带运营商检测
//!
//! 纯展示型功能：客户端启动时查一次自己的出口公网 IP 对应的 ISP
//! （中国电信/中国移动/中国联通，或国外对应的运营商名称），
//! 帮助用户判断游戏联机时是否发生了"跨运营商绕路"。
//!
//! 使用 ip-api.com 的免费查询接口：不带 IP 参数直接请求即可返回
//! "请求方自己" 的公网 IP + ISP + 地理位置信息，一次请求搞定，
//! 不需要额外先查一次"我的 IP 是什么"。
//!
//! 注意：ip-api.com 免费版不支持 HTTPS，这里用普通 HTTP 请求。

use serde::{Deserialize, Serialize};

const IP_API_URL: &str =
    "http://ip-api.com/json/?fields=status,message,query,isp,country,regionName,city,countryCode";

/// 出口公网 IP / ISP 检测结果，通过 Tauri 事件下发给前端展示
#[derive(Debug, Clone, Serialize)]
pub struct LocalIspInfo {
    /// 出口公网 IP
    pub public_ip: String,
    /// 宽带运营商（如 "中国电信"、"China Telecom" 等，取决于 ip-api 返回）
    pub isp: String,
    /// 国家
    pub country: String,
    /// 省份/地区
    pub region: String,
    /// 城市
    pub city: String,
}

/// ip-api.com 返回的原始 JSON 结构（仅取我们关心的字段）
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "regionName")]
    region_name: String,
    #[serde(default)]
    city: String,
}

/// 检测本机出口公网 IP 对应的宽带运营商。
///
/// 内部用 `tokio::task::spawn_blocking` 包裹同步的 `ureq` 调用，避免阻塞
/// async runtime 的工作线程。失败时返回 `Err`，调用方应静默处理（记日志即可），
/// 不应该弹窗打断用户。
pub async fn detect_local_isp() -> Result<LocalIspInfo, String> {
    let join_result = tokio::task::spawn_blocking(fetch_isp_info_blocking).await;

    match join_result {
        Ok(inner) => inner,
        Err(e) => Err(format!("查询运营商任务异常退出: {e}")),
    }
}

/// 同步阻塞版本的实际查询逻辑，必须在 `spawn_blocking` 中调用。
fn fetch_isp_info_blocking() -> Result<LocalIspInfo, String> {
    let resp = ureq::get(IP_API_URL)
        .timeout(std::time::Duration::from_secs(6))
        .call()
        .map_err(|e| format!("请求 ip-api.com 失败: {e}"))?;

    let body: IpApiResponse = resp
        .into_json()
        .map_err(|e| format!("解析 ip-api.com 响应失败: {e}"))?;

    if body.status != "success" {
        return Err(format!(
            "ip-api.com 返回失败状态: {}",
            if body.message.is_empty() {
                "unknown"
            } else {
                &body.message
            }
        ));
    }

    Ok(LocalIspInfo {
        public_ip: body.query,
        isp: body.isp,
        country: body.country,
        region: body.region_name,
        city: body.city,
    })
}

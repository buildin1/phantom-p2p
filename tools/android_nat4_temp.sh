#!/system/bin/sh
# Root Android 热点临时 NAT 加严脚本。
# 安全设计：只创建专用链，不清空全局规则。
# 用法示例：
#   su -c 'sh /data/local/tmp/android_nat4_temp.sh apply --wan rmnet_data0 --lan wlan0 --timeout 1800'
#   su -c 'sh /data/local/tmp/android_nat4_temp.sh status'
#   su -c 'sh /data/local/tmp/android_nat4_temp.sh restore'

set -u

CHAIN_NAT="TEMP_NAT4_POST"
CHAIN_FWD="TEMP_NAT4_FWD"
STATE_FILE="/data/local/tmp/android_nat4_temp.state"
LOCK_FILE="/data/local/tmp/android_nat4_temp.lock"

log() {
  echo "[nat4-temp] $*"
}

die() {
  echo "[nat4-temp] ERROR: $*" >&2
  exit 1
}

need_root() {
  uid="$(id -u 2>/dev/null || echo 1)"
  [ "$uid" = "0" ] || die "必须以 root 运行（用 su -c ...）"
}

find_iptables() {
  if command -v iptables >/dev/null 2>&1; then
    echo "iptables"
    return 0
  fi
  if command -v iptables-legacy >/dev/null 2>&1; then
    echo "iptables-legacy"
    return 0
  fi
  if [ -x /system/bin/iptables ]; then
    echo "/system/bin/iptables"
    return 0
  fi
  return 1
}

ipt() {
  "$IPT" "$@"
}

has_rule() {
  table="$1"
  shift
  ipt -t "$table" -C "$@" >/dev/null 2>&1
}

ensure_chain() {
  table="$1"
  chain="$2"
  if ! ipt -t "$table" -nL "$chain" >/dev/null 2>&1; then
    ipt -t "$table" -N "$chain" || die "创建链失败 $table/$chain"
  fi
}

delete_jump_if_exists() {
  table="$1"
  shift
  if has_rule "$table" "$@"; then
    ipt -t "$table" -D "$@" || die "删除跳转规则失败 table=$table"
  fi
}

flush_delete_chain() {
  table="$1"
  chain="$2"
  if ipt -t "$table" -nL "$chain" >/dev/null 2>&1; then
    ipt -t "$table" -F "$chain" >/dev/null 2>&1
    ipt -t "$table" -X "$chain" >/dev/null 2>&1
  fi
}

save_state() {
  prev_ipf="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
  {
    echo "WAN_IF=$WAN_IF"
    echo "LAN_IF=$LAN_IF"
    echo "PREV_IP_FORWARD=$prev_ipf"
  } > "$STATE_FILE" || die "写入状态文件失败"
}

load_state() {
  [ -f "$STATE_FILE" ] || die "状态文件不存在: $STATE_FILE"
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  [ -n "${WAN_IF:-}" ] || die "状态文件无效: WAN_IF 缺失"
  [ -n "${LAN_IF:-}" ] || die "状态文件无效: LAN_IF 缺失"
}

set_ip_forward() {
  value="$1"
  echo "$value" > /proc/sys/net/ipv4/ip_forward || die "设置 ip_forward=$value 失败"
}

apply_rules() {
  ensure_chain nat "$CHAIN_NAT"
  ensure_chain filter "$CHAIN_FWD"

  ipt -t nat -F "$CHAIN_NAT"
  ipt -t filter -F "$CHAIN_FWD"

  if ipt -t nat -A "$CHAIN_NAT" -o "$WAN_IF" -j MASQUERADE --random-fully >/dev/null 2>&1; then
    log "已启用 MASQUERADE --random-fully"
  else
    ipt -t nat -A "$CHAIN_NAT" -o "$WAN_IF" -j MASQUERADE || die "添加 MASQUERADE 失败"
    log "系统不支持 --random-fully，已回退为普通 MASQUERADE"
  fi

  ipt -t filter -A "$CHAIN_FWD" -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT || die "放行 LAN->WAN 失败"
  ipt -t filter -A "$CHAIN_FWD" -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || die "放行已建立回包失败"

  if ! has_rule nat POSTROUTING -o "$WAN_IF" -j "$CHAIN_NAT"; then
    ipt -t nat -I POSTROUTING 1 -o "$WAN_IF" -j "$CHAIN_NAT" || die "挂载 POSTROUTING 失败"
  fi

  if ! has_rule filter FORWARD -j "$CHAIN_FWD"; then
    ipt -t filter -I FORWARD 1 -j "$CHAIN_FWD" || die "挂载 FORWARD 失败"
  fi
}

restore_rules() {
  delete_jump_if_exists nat POSTROUTING -o "$WAN_IF" -j "$CHAIN_NAT"
  delete_jump_if_exists filter FORWARD -j "$CHAIN_FWD"
  flush_delete_chain nat "$CHAIN_NAT"
  flush_delete_chain filter "$CHAIN_FWD"
}

schedule_auto_restore() {
  timeout_secs="$1"
  [ "$timeout_secs" -gt 0 ] 2>/dev/null || return 0

  nohup sh -c "
    sleep $timeout_secs
    if [ -f '$STATE_FILE' ]; then
      sh '$0' restore >/dev/null 2>&1
    fi
  " >/dev/null 2>&1 &

  log "已设置自动恢复：${timeout_secs} 秒后执行 restore"
}

status_cmd() {
  log "iptables 可执行文件: $IPT"
  if [ -f "$STATE_FILE" ]; then
    log "当前状态: 已应用"
    cat "$STATE_FILE"
  else
    log "当前状态: 未应用"
  fi

  if ipt -t nat -nL "$CHAIN_NAT" >/dev/null 2>&1; then
    log "NAT 链存在: $CHAIN_NAT"
    ipt -t nat -S "$CHAIN_NAT"
  else
    log "NAT 链不存在"
  fi

  if ipt -t filter -nL "$CHAIN_FWD" >/dev/null 2>&1; then
    log "Filter 链存在: $CHAIN_FWD"
    ipt -t filter -S "$CHAIN_FWD"
  else
    log "Filter 链不存在"
  fi

  log "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"
}

usage() {
  cat <<EOF
用法:
  $0 apply --wan <iface> --lan <iface> [--timeout <seconds>]
  $0 restore
  $0 status
  $0 menu

说明:
  - 这是热点测试用的“本地临时 NAT 加严层”。
  - 它不会改变运营商 CGNAT 行为。
  - restore 只删除 TEMP_* 专用链，并恢复原始 ip_forward。
EOF
}

list_ifaces() {
  ip -br link 2>/dev/null || ip link 2>/dev/null || true
}

guess_wan_if() {
  route_dev="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
  if [ -n "$route_dev" ] && ip link show "$route_dev" >/dev/null 2>&1; then
    echo "$route_dev"
    return 0
  fi

  for n in rmnet_data0 rmnet0 ccmni0 ccmni1 wwan0 usb0; do
    if ip link show "$n" >/dev/null 2>&1; then
      echo "$n"
      return 0
    fi
  done
  echo ""
}

guess_lan_if() {
  for n in ap0 swlan0 wlan0; do
    if ip link show "$n" >/dev/null 2>&1; then
      addr_line="$(ip -4 addr show dev "$n" 2>/dev/null | awk '/inet / {print $2; exit}')"
      case "$addr_line" in
        192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2*.*|172.30.*|172.31.*|10.*)
          echo "$n"
          return 0
          ;;
      esac
    fi
  done

  for n in wlan0 ap0 swlan0; do
    if ip link show "$n" >/dev/null 2>&1; then
      echo "$n"
      return 0
    fi
  done
  echo ""
}

apply_cmd() {
  if [ -f "$STATE_FILE" ]; then
    die "规则已应用，请先 restore"
  fi

  echo $$ > "$LOCK_FILE" 2>/dev/null || true
  save_state
  set_ip_forward 1
  apply_rules
  rm -f "$LOCK_FILE" 2>/dev/null || true
  log "已应用: WAN=$WAN_IF LAN=$LAN_IF"
  schedule_auto_restore "$TIMEOUT_SECS"
}

restore_cmd() {
  if [ ! -f "$STATE_FILE" ]; then
    log "无需恢复（状态文件不存在）"
    return 0
  fi

  load_state
  restore_rules
  set_ip_forward "${PREV_IP_FORWARD:-0}"
  rm -f "$STATE_FILE" "$LOCK_FILE" 2>/dev/null || true
  log "已恢复；ip_forward=${PREV_IP_FORWARD:-0}"
}

menu_cmd() {
  while :; do
    echo ""
    echo "==== NAT4 临时实验菜单 ===="
    echo "1) 查看网卡列表"
    echo "2) 自动检测并应用临时 NAT 加严"
    echo "3) 查看状态"
    echo "4) 一键恢复规则"
    echo "5) 退出"
    printf "请选择 [1-5]: "
    read -r choice || exit 1

    case "$choice" in
      1)
        list_ifaces
        ;;
      2)
        if [ -f "$STATE_FILE" ]; then
          log "规则已应用，请先选择 4 恢复"
          continue
        fi

        default_wan="$(guess_wan_if)"
        default_lan="$(guess_lan_if)"

        if [ -z "$default_wan" ] || [ -z "$default_lan" ]; then
          log "自动检测网卡失败，进入手动输入模式"
          echo "当前网卡信息："
          list_ifaces
          printf "请输入 WAN 网卡（蜂窝上行，如 rmnet_data0）: "
          read -r wan_input
          printf "请输入 LAN 网卡（热点下行，如 wlan0/ap0）: "
          read -r lan_input
          WAN_IF="$wan_input"
          LAN_IF="$lan_input"
        else
          WAN_IF="$default_wan"
          LAN_IF="$default_lan"
          log "自动检测结果: WAN=$WAN_IF, LAN=$LAN_IF"
          printf "是否使用自动检测结果并继续？[Y/n]: "
          read -r yn
          case "${yn:-Y}" in
            n|N)
              echo "当前网卡信息："
              list_ifaces
              printf "请输入 WAN 网卡（蜂窝上行，如 rmnet_data0）: "
              read -r wan_input
              printf "请输入 LAN 网卡（热点下行，如 wlan0/ap0）: "
              read -r lan_input
              WAN_IF="$wan_input"
              LAN_IF="$lan_input"
              ;;
          esac
        fi

        printf "自动恢复秒数 [1800]: "
        read -r timeout_input

        TIMEOUT_SECS="${timeout_input:-1800}"

        parse_apply_args --wan "$WAN_IF" --lan "$LAN_IF" --timeout "$TIMEOUT_SECS"
        apply_cmd
        ;;
      3)
        status_cmd
        ;;
      4)
        restore_cmd
        ;;
      5)
        log "已退出"
        exit 0
        ;;
      *)
        log "无效选项"
        ;;
    esac
  done
}

parse_apply_args() {
  WAN_IF=""
  LAN_IF=""
  TIMEOUT_SECS=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --wan)
        shift
        [ "$#" -gt 0 ] || die "--wan 后必须跟网卡名"
        WAN_IF="$1"
        ;;
      --lan)
        shift
        [ "$#" -gt 0 ] || die "--lan 后必须跟网卡名"
        LAN_IF="$1"
        ;;
      --timeout)
        shift
        [ "$#" -gt 0 ] || die "--timeout 后必须跟秒数"
        TIMEOUT_SECS="$1"
        ;;
      *)
        die "未知参数: $1"
        ;;
    esac
    shift
  done

  [ -n "$WAN_IF" ] || die "缺少 --wan"
  [ -n "$LAN_IF" ] || die "缺少 --lan"
  [ "$WAN_IF" != "$LAN_IF" ] || die "WAN/LAN 不能是同一网卡"

  ip link show "$WAN_IF" >/dev/null 2>&1 || die "WAN 网卡不存在: $WAN_IF"
  ip link show "$LAN_IF" >/dev/null 2>&1 || die "LAN 网卡不存在: $LAN_IF"
}

main() {
  need_root
  IPT="$(find_iptables || true)"
  [ -n "$IPT" ] || die "设备上未找到 iptables"

  cmd="${1:-}"
  case "$cmd" in
    apply)
      shift
      parse_apply_args "$@"
      apply_cmd
      ;;
    restore)
      restore_cmd
      ;;
    status)
      status_cmd
      ;;
    menu)
      menu_cmd
      ;;
    "")
      menu_cmd
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

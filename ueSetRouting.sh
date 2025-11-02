# 清理舊規則（可重複執行）
ip rule del from 10.60.0.1/32 table 100 2>/dev/null || true
ip rule del from 10.63.0.1/32 table 101 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
ip route flush table 101 2>/dev/null || true

# 10.60.0.1 → ueTun1；10.63.0.1 → ueTun2
ip rule add from 10.60.0.1/32 lookup 100 prio 10000
ip route add default dev ueTun1 table 100

ip rule add from 10.63.0.1/32 lookup 101 prio 10001
ip route add default dev ueTun2 table 101

# 驗證：應顯示經 ueTun1/ueTun2
ip route get 192.168.58.20 from 10.60.0.1
ip route get 192.168.59.20 from 10.63.0.1
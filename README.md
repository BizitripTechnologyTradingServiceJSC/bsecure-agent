# bsecure-agent

Agent Go (không phụ thuộc thư viện ngoài) chạy trên từng server: gửi heartbeat và log SSH lên Control Panel ([bsecure-cp](https://github.com/BizitripTechnologyTradingServiceJSC/bsecure-cp)), nhận lệnh đã ký và thực thi trên nftables.

- Chỉ gọi ra ngoài, không mở cổng.
- Chỉ chạy `block_ip` / `unblock_ip`, không có shell. Dùng bảng riêng `inet fwctl`, block có timeout tự hết.
- Mỗi lệnh phải có chữ ký Ed25519 hợp lệ, đúng server, chưa hết hạn, chưa dùng lại; IP trong `ADMIN_ALLOWLIST` và loopback/multicast luôn bị từ chối.
- `DRY_RUN=true` mặc định.

```bash
go build -o fwagent ./cmd/fwagent
PANEL_URL=https://panel.example ENROLL_TOKEN=... PANEL_PUBKEY=<từ npm run keygen ở bsecure-cp> \
ADMIN_ALLOWLIST=<IP quản trị, phân tách bằng dấu phẩy> ./fwagent
```
## Thu thập (chỉ đọc)
- **Inventory** mỗi 5 phút → `/agent/inventory`: cổng đang nnghe (từ `/proc/net/*`, kèm tiến trình), OS/kernel, và với **sshd / nginx / tinyproxy**: phiên bản, đang chạy hay không, các thiết lập bảo mật đã phân tích, hash cấu hình. Không gửi nguyên file cấu hình hay mật khẩu (BasicAuth chỉ báo "có/không").
- **Log** → events đã chuẩn hoá và che dữ liệu nhạy cảm: SSH (`AUTH_LOG`), nginx access (`NGINX_ACCESS_LOG`: dò quét như `/.env`, `wp-login.php`, path traversal, SQLi/XSS, và 401), syslog (`SYSLOG`: sudo thất bại, OOM kill, user mới, segfault). Query string và User-Agent bị bỏ.
- Agent chỉ báo dữ kiện; việc chấm điểm nằm ở Control Panel. Agent **chưa sửa cấu hình phần mềm** nào.

Biến môi trường: `PANEL_URL`, `ENROLL_TOKEN`, `PANEL_PUBKEY` (nên ghim), `AGENT_NAME`, `STATE_DIR` (/var/lib/fwagent), `AUTH_LOG` (/var/log/auth.log), `NGINX_ACCESS_LOG` (/var/log/nginx/access.log), `SYSLOG` (/var/log/syslog); để trống để tắt nguồn đó, `ADMIN_ALLOWLIST`, `DRY_RUN`.
systemd: `deploy/fwagent.service`. Test: `go test ./...`

Chưa chạy `nft` thật; thử trên máy lab có console trước khi đặt `DRY_RUN=false`.

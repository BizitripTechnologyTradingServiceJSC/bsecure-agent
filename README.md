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
- **Inventory** mỗi 5 phút → `/agent/inventory`: cổng đang nghe (từ `/proc/net/*`, kèm tiến trình), OS/kernel, và với **sshd / nginx / tinyproxy**: phiên bản, đang chạy hay không, các thiết lập bảo mật đã phân tích, hash cấu hình. Không gửi nguyên file cấu hình hay mật khẩu (BasicAuth chỉ báo "có/không").
- **Log** → events đã chuẩn hoá và che dữ liệu nhạy cảm: SSH (`AUTH_LOG`), nginx access (`NGINX_ACCESS_LOG`: dò quét như `/.env`, `wp-login.php`, path traversal, SQLi/XSS, và 401), syslog (`SYSLOG`: sudo thất bại, OOM kill, user mới, segfault). Query string và User-Agent bị bỏ.
- Agent chỉ báo dữ kiện; việc chấm điểm nằm ở Control Panel. Agent **chưa sửa cấu hình phần mềm** nào.

## Đổi cấu hình phần mềm (tắt mặc định)
Bật bằng `ALLOW_CONFIG_CHANGES=true` (kèm `deploy/fwagent-config.conf` nếu chạy bằng systemd). Agent chỉ nhận lệnh `set_config` đã ký cho **danh mục cố định** (`internal/catalog.go`), chỉ theo hướng siết chặt:

| Phần mềm | Thiết lập được đổi |
|---|---|
| sshd | `PermitRootLogin` (no/prohibit-password), `PasswordAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `MaxAuthTries` 2–6 |
| nginx | `server_tokens off`, `ssl_protocols` (TLSv1.2 TLSv1.3 / TLSv1.3) |
| tinyproxy | `Allow` (IP/CIDR, từ chối dải quá rộng như 0.0.0.0/0), `ConnectPort`, `Listen` |

Quy trình mỗi lần đổi: kiểm tra khoá không bị khoá cửa (sshd cần có `authorized_keys`) → sao lưu → ghi file nguyên tử → `sshd -t` / `nginx -t` → reload → **kiểm tra giá trị hiệu lực** (`sshd -T`, đọc lại cấu hình nginx, tinyproxy còn chạy) → bất kỳ bước nào lỗi thì **khôi phục bản cũ** và reload lại. Nếu thành công, thay đổi ở trạng thái `pending_confirm` và **tự hoàn tác sau 30–900 giây (mặc định 120)** nếu không có lệnh `confirm_config` từ người dùng (kể cả khi agent khởi động lại giữa chừng). sshd ghi vào drop-in `00-bsecure.conf`, nginx sửa các dòng có sẵn (hoặc tạo `conf.d/00-bsecure.conf`), tinyproxy sửa file cấu hình. Mỗi phần mềm chỉ có 1 thay đổi chờ xác nhận tại một thời điểm. `DRY_RUN=true` chỉ trả về diff, không ghi gì.

Biến môi trường: `PANEL_URL`, `ENROLL_TOKEN`, `PANEL_PUBKEY` (nên ghim), `AGENT_NAME`, `STATE_DIR` (/var/lib/fwagent), `AUTH_LOG` (/var/log/auth.log), `NGINX_ACCESS_LOG` (/var/log/nginx/access.log), `SYSLOG` (/var/log/syslog); để trống để tắt nguồn đó, `ADMIN_ALLOWLIST`, `DRY_RUN`, `ALLOW_CONFIG_CHANGES` (false).
systemd: `deploy/fwagent.service`. Test: `go test ./...`

- Kết quả lệnh được lưu vào `STATE_DIR/outbox.json` khi panel không với tới được và gửi lại theo đúng thứ tự, nên panel không bỏ lỡ kết quả "đã tự hoàn tác".
- Không bao giờ chặn IP Cloudflare edge hay IP trong `ADMIN_ALLOWLIST`; gỡ chặn thì luôn được.
- Mất `state.json` (cài lại máy) thì admin phải bấm **Reset enroll** trên panel trước khi agent đăng ký lại.

Chưa chạy `nft` thật; thử trên máy lab có console trước khi đặt `DRY_RUN=false`.

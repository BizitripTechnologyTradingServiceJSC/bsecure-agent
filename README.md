# bsecure-agent

Agent Go (không phụ thuộc thư viện ngoài) chạy trên từng server: gửi heartbeat, inventory và log lên Control Panel ([bsecure-cp](https://github.com/BizitripTechnologyTradingServiceJSC/bsecure-cp)), nhận lệnh đã ký và thực thi trên nftables hoặc cấu hình phần mềm.

- Chỉ gọi ra ngoài, không mở cổng. Kết nối tới panel bằng HTTPS, có mTLS (chứng chỉ client riêng cho mỗi server).
- Chỉ chạy một tập hành động cố định (`block_ip`, `unblock_ip`, `set_config`, `confirm_config`), không có shell. Firewall dùng bảng riêng `inet fwctl`, block có timeout tự hết.
- Mỗi lệnh phải có chữ ký Ed25519 hợp lệ, đúng server, chưa hết hạn, chưa dùng lại (nonce lưu xuống đĩa, không bị phát lại sau khi khởi động lại).
- Không bao giờ chặn IP trong `ADMIN_ALLOWLIST`, loopback/multicast hay Cloudflare edge (danh sách có sẵn + danh sách panel gửi xuống qua heartbeat); gỡ chặn thì luôn được.
- `DRY_RUN=true` mặc định.

```bash
go build -o fwagent ./cmd/fwagent
PANEL_URL=https://panel.example:8443 ENROLL_TOKEN=... PANEL_PUBKEY=<từ npm run keygen ở bsecure-cp> \
PANEL_CA_FILE=/etc/fwagent/ca.crt AGENT_CERT_FILE=/etc/fwagent/agent.crt AGENT_KEY_FILE=/etc/fwagent/agent.key \
AGENT_NAME=web-01 ADMIN_ALLOWLIST=<IP quản trị, phân tách bằng dấu phẩy> ./fwagent
```
Chứng chỉ tạo bằng `scripts/gen-certs.sh` trong bsecure-cp (CN phải trùng `AGENT_NAME`). `http://` bị từ chối trừ khi đặt `ALLOW_INSECURE_HTTP=true` (chỉ để thử cục bộ).

## Thu thập (chỉ đọc)
- **Inventory** mỗi 5 phút: cổng đang nghe (từ `/proc/net/*`, kèm tiến trình), OS/kernel, và với **sshd / nginx / tinyproxy**: phiên bản, đang chạy hay không, các thiết lập bảo mật đã phân tích, hash cấu hình. Không gửi nguyên file cấu hình hay mật khẩu (BasicAuth chỉ báo "có/không").
- **Log** → events đã chuẩn hoá và che dữ liệu nhạy cảm:
  - SSH (`AUTH_LOG`): đếm **số lần thử**, không đếm số dòng log (một lần đăng nhập sai không còn bị tính 2 lần); bắt cả scanner chỉ dùng key (dòng `[preauth]`).
  - nginx access (`NGINX_ACCESS_LOG`): dò quét như `/.env`, `wp-login.php`, path traversal, SQLi/XSS, và 401. Query string và User-Agent bị bỏ.
  - syslog (`SYSLOG`): sudo thất bại, OOM kill, user mới, segfault.
- Phát hiện xoay vòng log theo danh tính file (không chỉ theo kích thước).
- **Nấu ngay khi đọc**: sự kiện có IP được gộp trong bộ nhớ theo (phút, loại, IP) và gửi lên `/agent/rollups` dưới dạng số đếm + một dòng mẫu (đã bỏ giờ/host, IP thành `<ip>`); tên user chỉ gửi dạng băm 8 hex. Sự kiện không có IP (sudo, OOM...) gửi riêng qua `/agent/events`. Đọc gần thời gian thực: inotify đánh thức vòng lặp (gộp ≤5 lần/giây), có thêm vòng quét an toàn mỗi 10 giây; một nguồn tích đủ 10 lần thử thì gửi sớm (tối đa 1 lần/2 giây).
- Agent chỉ báo dữ kiện; việc chấm điểm nằm ở Control Panel.

## Đổi cấu hình phần mềm (tắt mặc định)
Bật bằng `ALLOW_CONFIG_CHANGES=true` (kèm `deploy/fwagent-config.conf` nếu chạy bằng systemd). Agent chỉ nhận lệnh `set_config` đã ký cho **danh mục cố định** (`internal/catalog.go`), chỉ theo hướng siết chặt:

| Phần mềm | Thiết lập được đổi |
|---|---|
| sshd | `PermitRootLogin` (no/prohibit-password), `PasswordAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `MaxAuthTries` 2–6 |
| nginx | `server_tokens off`, `ssl_protocols` (TLSv1.2 TLSv1.3 / TLSv1.3) |
| tinyproxy | `Allow` (IP/CIDR, từ chối dải quá rộng như 0.0.0.0/0), `ConnectPort`, `Listen` |

Quy trình mỗi lần đổi: kiểm tra không tự khoá cửa (sshd cần có `authorized_keys`) → sao lưu → ghi file nguyên tử → `sshd -t` / `nginx -t` → reload → **kiểm tra giá trị hiệu lực** (`sshd -T`, đọc lại cấu hình nginx, tinyproxy còn chạy) → bất kỳ bước nào lỗi thì **khôi phục bản cũ** và reload lại. Nếu thành công, thay đổi ở trạng thái `pending_confirm` và **tự hoàn tác sau 30–900 giây (mặc định 120)** nếu không có lệnh `confirm_config` (kể cả khi agent khởi động lại giữa chừng). Hoàn tác thất bại thì thử lại giãn dần 1 phút → 1 giờ và chỉ báo lỗi một lần.

Reload dùng `systemctl`; trên máy không có systemd (container, OpenRC) thì dùng `nginx -s reload`, HUP cho sshd và USR1 cho tinyproxy qua pid file.

## Không làm nặng server
Agent được thiết kế để không bao giờ là lý do server chậm:
- **Đọc log**: lọc nhanh không cấp phát bộ nhớ trước khi chạy regex (~1 µs/dòng nginx, nhanh hơn ~6 lần so với regex mọi dòng); chỉ chiếm tối đa **10% một core** (sau mỗi lượt đọc tốn *d* giây thì nghỉ *9d*); nếu tụt quá 8 MiB thì bỏ qua đoạn cũ, ghi vào bộ đếm `dropped` và log `skipped ahead`.
- **Bộ nhớ**: tối đa 20 000 bộ đếm, 500 sự kiện hiếm, 16 user/bộ đếm; `GOMEMLIMIT` mềm 96 MiB; `GOMAXPROCS` ≤ 2; nice 10.
- **Inventory**: cache phiên bản (1 giờ) và kết quả `sshd -T` (theo hash cấu hình), chỉ duyệt `/proc/*/fd` khi có cổng nghe mới, chỉ gửi lại khi thay đổi (hoặc mỗi 30 phút); số IP đang chặn của nft được cache 2 phút.
- **systemd** (`deploy/fwagent.service`): `Nice=10`, `CPUWeight=20`, `CPUQuota=15%`, `MemoryHigh=96M`, `MemoryMax=160M`, `TasksMax=64`, `IOSchedulingClass=idle`, `OOMScoreAdjust=500`.
- Agent tự báo CPU %, RSS, dòng/giây, số bị bỏ trong heartbeat (`stats`) để panel hiển thị.

Đo thực tế (4 core, máy sinh log chạy cùng máy, `DRY_RUN`, log nginx + sshd): 20 000 dòng/giây ≈ 1,5% một core; 100 000 dòng/giây ≈ 4,7% một core, RSS ~16 MB, vẫn ghi nhận ~98% số lần thử đáng ngờ.

## Biến môi trường
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PANEL_URL` | (bắt buộc) | `https://...` |
| `PANEL_CA_FILE`, `AGENT_CERT_FILE`, `AGENT_KEY_FILE` | | mTLS: CA riêng (không dùng CA hệ thống) và chứng chỉ client |
| `ENROLL_TOKEN`, `PANEL_PUBKEY` | | đăng ký lần đầu; nên ghim khoá công khai của panel |
| `AGENT_NAME` | hostname | phải trùng CN của chứng chỉ |
| `STATE_DIR` | `/var/lib/fwagent` | token, lệnh chờ xác nhận, outbox, nonce |
| `AUTH_LOG`, `NGINX_ACCESS_LOG`, `SYSLOG` | `/var/log/...` | để trống để tắt nguồn đó |
| `ADMIN_ALLOWLIST` | | IP/CIDR không bao giờ bị chặn |
| `DRY_RUN` | `true` | |
| `ALLOW_CONFIG_CHANGES` | `false` | |
| `ALLOW_INSECURE_HTTP` | `false` | chỉ để thử |
| `PANEL_ALLOWED_CIDRS` | trống | Chạy qua VPN: chỉ kết nối nếu địa chỉ panel nằm trong các dải này, ví dụ `100.64.0.0/10` (NetBird). Tên panel phân giải ra địa chỉ ngoài dải thì agent từ chối |
| `OVERLAY_CIDRS` | `100.64.0.0/10` | Dải VPN không bao giờ bị chặn (đổi nếu NetBird dùng dải khác) |

systemd: `deploy/fwagent.service`. Test: `go test ./...`; kiểm thử đầu cuối bằng Docker: `lab/e2e.sh` trong bsecure-cp.

## Vận hành
- Kết quả lệnh được lưu vào `STATE_DIR/outbox.json` khi panel không với tới được và gửi lại theo đúng thứ tự.
- Mất `state.json` (cài lại máy) thì admin phải bấm **Reset enroll** trên panel trước khi agent đăng ký lại.
- Trước khi đặt `DRY_RUN=false` trên server thật: chạy lab, rồi canary trên một server ít quan trọng, luôn có đường vào console.

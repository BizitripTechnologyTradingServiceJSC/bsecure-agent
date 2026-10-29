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
Biến môi trường: `PANEL_URL`, `ENROLL_TOKEN`, `PANEL_PUBKEY` (nên ghim), `AGENT_NAME`, `STATE_DIR` (/var/lib/fwagent), `LOG_FILE` (/var/log/auth.log), `ADMIN_ALLOWLIST`, `DRY_RUN`.
systemd: `deploy/fwagent.service`. Test: `go test ./...`

Chưa chạy `nft` thật; thử trên máy lab có console trước khi đặt `DRY_RUN=false`.

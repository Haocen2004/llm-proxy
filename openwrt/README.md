# OpenWrt 部署文件

当前产物面向 `aarch64-unknown-linux-musl`。将 `llmproxyd` 安装为 `/usr/bin/llmproxyd`，并复制：

```text
etc/config/dshp       -> /etc/config/dshp
etc/init.d/llmproxyd  -> /etc/init.d/llmproxyd
etc/dshp/llmproxyd.toml -> /etc/dshp/llmproxyd.toml
```

另行创建权限为 `0600` 的 `/etc/dshp/llmproxyd.env`，内容至少包括：

```text
DSHP_PSK=...
DSHP_WEBUI_TOKEN=...
DSHP_STATS_FILE=/overlay/dshp/stats.toml
```

然后执行：

```sh
mkdir -p /overlay/dshp
chmod 700 /overlay/dshp
chmod 600 /etc/dshp/llmproxyd.env
/etc/init.d/llmproxyd enable
/etc/init.d/llmproxyd restart
```

默认监听 `127.0.0.1:19000`，通过 UCI 的 `listen` 选项改为 LAN 地址前，应先配置防火墙和访问控制。

## OpenWrt 作为局域网客户端

如果服务端运行在远端 WSS 地址，可额外安装 `llmproxyc` 和 `etc/init.d/llmproxyc`，然后在 `/etc/config/dshp` 启用客户端段：

```text
config client 'client'
    option enabled '1'
    option listen '0.0.0.0:8080'
    option server 'wss://llmproxy.example.com'
    option upstream_host 'localhost'
    # 直连兜底（可选）：链路不可用时改走这个上游前缀。**纯前缀拼接** ⇒
    # 只写 scheme://host[:port]，**不要带 `/v1`**（否则拼成 /v1/v1/...）；
    # 且必须是 http://（客户端不支持 TLS 上游）。
    option upstream_fallback 'http://192.0.2.10:3000'
```

> **上面的域名与上游地址都是占位符**：真实部署值写在部署机自己的 `/etc/config/dshp` 里，
> **不要入库**（原因见本地归档 `dev-notes/publication-checklist.md`，`dev-notes/` 不进版本库）。
> `192.0.2.0/24` 是文档用地址段（TEST-NET-1）。

配好之后，链路不可用时不会再回 502「DSHP 链路不可用，且未配置 --upstream-fallback」，
而是**直连该上游**继续服务；恢复链路后自动切回 WS。实测：停掉服务端，经客户端发一次请求，
拿到的是上游自己的 `401 Invalid token ... new_api_error`（说明请求真的直连到了上游）。

客户端的 LAN 监听是显式授权功能，procd 会传入 `--allow-lan`；请只在可信 LAN 使用，并通过防火墙限制来源。SDK 的 `base_url` 应指向 `http://<OpenWrt 地址>:8080`。

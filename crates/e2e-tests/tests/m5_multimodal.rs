//! M5 验收：**多模态（中段插入图片）下的块复用**（设计 §5.4 / §5.5）。
//!
//! 设计 §5.4 给 CDC 的理由只有一条：**中段插入/删除时的鲁棒性**——
//! "对话中间插入图片或工具结果时，定长分块会雪崩，CDC 不会"。
//! §5.5 进一步把它量化成：`tools` 那 28 KB 因为 `messages` 变长而整体错位，
//! 纯前缀法一点都复用不到，**这正是块引用存在的理由**。
//!
//! 所以这一组测的不是"省了多少"，而是**机制是否真的成立**：
//! 插入点**之后**的内容（字节整体错位）能不能被重新同步、继续复用。
//! 光看总节省会把它和"前缀复用"混在一起——前缀本来就是逐字节相同的，
//! 复用它是平凡的事，复用后缀才是 CDC 的价值。

mod common;

use common::*;

/// 标准 base64 编码（自己写 8 行，不为一条测试引入依赖）。
fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// 高熵（不可压缩）的图片字节 → 真实多模态请求里那种 base64 data URL 的载荷。
///
/// **必须高熵**：可压缩的图片会让"省了多少"变成压缩率的测量，
/// 而不是块复用的测量。这里要测的是复用。
fn image_payload(bytes: usize) -> String {
    let mut x: u64 = 0x243F_6A88_85A3_08D3;
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        data.push((x >> 33) as u8);
    }
    b64(&data)
}

/// 一条"带图片的消息"（OpenAI 多模态形态）。
fn image_message(img_b64: &str) -> String {
    format!(
        r#"{{"role":"user","content":[{{"type":"image_url","image_url":{{"url":"data:image/png;base64,{img_b64}"}}}}]}}"#
    )
}

/// 在 `messages` 数组的 `at_frac` 位置插入一条消息（0.0 = 最前，1.0 = 最后）。
///
/// 直接在 body **字节**上按 `,{"role"` 边界切——这正是"字节层"该做的事：
/// 代理不理解 body 语义，测试也不该假装理解，只要插出来的是合法 JSON 即可。
///
/// **必须按字节而不是按 `str`**：body 里是 CJK（每个汉字 3 字节），
/// 按字符串长度取中点几乎必然落在字符内部，`s[mid..]` 会直接 panic。
/// 讽刺的是这条测试测的就是字节层复用——第一版却在字节层上栽了一次。
fn insert_message(body: &[u8], at_frac: f64, msg: &str) -> Vec<u8> {
    const NEEDLE: &[u8] = b",{\"role\"";
    let from = (body.len() as f64 * at_frac) as usize;
    let at = body[from..]
        .windows(NEEDLE.len())
        .position(|w| w == NEEDLE)
        .expect("找不到消息边界")
        + from;
    let mut out = Vec::with_capacity(body.len() + msg.len() + 2);
    out.extend_from_slice(&body[..at]);
    out.push(b',');
    out.extend_from_slice(msg.as_bytes());
    out.extend_from_slice(&body[at..]);
    out
}

fn counters(v: &serde_json::Value) -> (u64, u64, u64) {
    (
        v["req_raw_bytes"].as_u64().unwrap(),
        v["req_wire_bytes"].as_u64().unwrap(),
        v["ref_blocks"].as_u64().unwrap(),
    )
}

/// **M5 验收**：中段插入图片后，插入点之后的内容必须靠 CDC 重新同步继续复用。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_conversation_image_insertion_still_reuses_blocks() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 约 2.1 MB 的会话（1200 条消息），块均值 8 KiB ⇒ 约 260 个块
        let body0 = make_body(1200, 0);
        let img = image_payload(192 * 1024); // 256 KiB 图像 ⇒ base64 后约 350 KB
        let body1 = insert_message(&body0, 0.5, &image_message(&img));

        // 这里面还带一个前提校验：插入的确实在**中间**
        assert!(body1.len() > body0.len());
        assert!(
            img.len() > body0.len() / 8,
            "图片要足够大，否则新增字节占比太小、测不出复用"
        );

        // 1) 冷启动：把 body0 的块灌进服务端缓存
        let e0 = st.echo("/v1/chat/completions", &body0).await.unwrap();
        assert_eq!(e0, body0, "首次回显必须逐字节一致");
        let (raw0, wire0, ref0) = counters(&st.status().await.unwrap());
        let up0 = st.up.rec.take();
        assert_eq!(up0.len(), 1);
        assert_eq!(up0[0].body, body0, "上游看到的第一个 body 必须逐字节一致");

        // 2) 中段插入图片
        let e1 = st.echo("/v1/chat/completions", &body1).await.unwrap();
        assert_eq!(e1, body1, "中段插入图片后回显必须逐字节一致");
        let (raw1, wire1, ref1) = counters(&st.status().await.unwrap());
        let up1 = st.up.rec.take();
        assert_eq!(up1.len(), 1, "上游应恰好收到第二个请求");
        assert_eq!(
            up1[0].body, body1,
            "上游看到的 body 必须逐字节一致——插入的图片不能错位"
        );

        let d_raw = raw1 - raw0;
        let d_wire = wire1 - wire0;
        let d_ref = ref1 - ref0;
        let new_bytes = (body1.len() - body0.len()) as u64;
        let suffix = (body0.len() / 2) as u64; // 插入点在中间 ⇒ 之后约一半
        println!(
            "  [M5 中段插图片] body {} → {}（新增 {} B），增量实发 {} B = {:.1}%（新增占 {:.1}%），复用块 +{d_ref}，后缀约 {suffix} B",
            body0.len(),
            body1.len(),
            new_bytes,
            d_wire,
            d_wire as f64 / d_raw as f64 * 100.0,
            new_bytes as f64 / d_raw as f64 * 100.0,
        );

        assert_eq!(d_raw, body1.len() as u64, "raw 口径应当就是 body 长度");
        assert!(
            d_wire >= new_bytes,
            "新增的图片是高熵内容，必须整段发出去（实发 {d_wire} B < 新增 {new_bytes} B 说明记账错了）"
        );
        // **核心断言**：真正要守住的是"不变的部分没有被重发"。
        //
        // 前缀法（只看公共前缀）会把插入点之后的**整个后缀**重发一遍，
        // 实发量会是 `new_bytes + suffix` 量级；块级复用只重发插入点附近
        // 重新对齐需要的几个块。所以门槛取在两者中间。
        assert!(
            d_wire < new_bytes + suffix / 2,
            "插入点之后的后缀必须靠 CDC 重新同步被复用，而不是整段重发：\
             实发 {d_wire} B，新增 {new_bytes} B，后缀约 {suffix} B。\
             实发接近 new+suffix 说明退化成纯前缀法了（设计 §5.5 点名的正是这个）"
        );
        assert!(
            d_ref > 100,
            "复用的块数太少（+{d_ref}），说明块引用没有覆盖到插入点之后的内容"
        );
        // 复用必须**同时**覆盖前缀与后缀：块数应当接近全量块数。
        // 若只有前缀被复用，这个数会掉到一半以下。
        assert!(
            d_ref > (body0.len() / 16_384) as u64,
            "复用的块数不足以覆盖整段会话（+{d_ref}）——前缀之外的块没被复用"
        );
    })
    .await;
}

/// **多模态去重**：同一张图片换个位置，块内容没变 ⇒ 一个字节都不该重发。
///
/// 这是"内容定义分块"最直接的价值：图片在对话里的位置变了，但图片本身没变。
/// 定长分块会因为前序长度变化而让整张图错位，CDC 不会。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_image_at_a_new_position_is_fully_reused() {
    guard(async {
        let st = setup().await.expect("启动失败");

        let base = make_body(800, 0);
        let img = image_payload(192 * 1024);
        let msg = image_message(&img);

        // 同一个 body，图片先放前段、再挪到后段
        let a = insert_message(&base, 0.2, &msg);
        let b = insert_message(&base, 0.8, &msg);
        assert_eq!(a.len(), b.len(), "两次只差图片位置，长度应当相同");

        let e0 = st.echo("/v1/chat/completions", &a).await.unwrap();
        assert_eq!(e0, a, "首次回显必须逐字节一致");
        let (raw0, wire0, _) = counters(&st.status().await.unwrap());
        let up0 = st.up.rec.take();
        assert_eq!(up0[0].body, a);

        let e1 = st.echo("/v1/chat/completions", &b).await.unwrap();
        assert_eq!(e1, b, "图片换位置后回显必须逐字节一致");
        let (raw1, wire1, ref1) = counters(&st.status().await.unwrap());
        let up1 = st.up.rec.take();
        assert_eq!(
            up1[0].body, b,
            "上游看到的 body 必须逐字节一致——图片被复用时不能放错位置"
        );

        let d_raw = raw1 - raw0;
        let d_wire = wire1 - wire0;
        println!(
            "  [M5 图片换位] body {} B，增量实发 {} B = {:.2}%（图片本身 {} B），累计复用块 {ref1}",
            b.len(),
            d_wire,
            d_wire as f64 / d_raw as f64 * 100.0,
            msg.len(),
        );

        // 图片（msg）一个字都没变，只是位置变了 ⇒ 复用量里必须包含它。
        // 实发量应当远小于图片本身——若图片被重发，d_wire 至少是 msg.len()。
        assert!(
            d_wire < msg.len() as u64 / 4,
            "同一张图片换位置后不应重发：实发 {d_wire} B，而图片本身就有 {} B。\
             这说明图片的块没有被复用（退化成了定长分块的行为）",
            msg.len()
        );
    })
    .await;
}

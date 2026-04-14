# Chimera_Server

**Languages:** [简体中文](README.md) | [English](README.en.md) | [Русский](README.ru.md) | **فارسی**

## معرفی پروژه

### هدف پروژه
Chimera_Server یک هسته سرویس شبکه مبتنی بر Rust است که هدف آن بیشترین سازگاری ممکن با پروژه
متن‌باز **xray-core** است. در مرحله فعلی، تمرکز اصلی روی **بخش پیکربندی inbound و رفتار
پروتکل‌های ورودی** قرار دارد تا نام فیلدها، مقدارهای پیش‌فرض، روند handshake و semantics اجرایی تا
حد ممکن با xray-core اصلی هماهنگ باشند.

### وضعیت فعلی
- منطق parsing و dispatch برای ورودی‌ها به‌صورت فعال در حال توسعه است و در حال حاضر VMess،
  VLESS، Trojan و سایر پروتکل‌های رایج ورودی در اولویت هستند.
- ماژول‌های outbound، routing و policy هنوز در حال طراحی هستند و فعلاً فقط پیاده‌سازی‌های پایه یا
  موقت برای آن‌ها وجود دارد.
- مخزن به سه بخش `chimera_server_app` (ورودی برنامه)، `chimera_server_lib` (کتابخانه اصلی) و
  `chimera_cli` (ابزار CLI کمکی) تقسیم شده است.

### پیاده‌سازی مرجع
برای کاهش فاصله با xray-core، بخشی از منطق parsing ورودی و مدیریت پروتکل‌ها از پروژه
جامعه‌محور [shoes](https://github.com/cfal/shoes) الهام گرفته است. رویکرد آن در handshake،
رفتار پیش‌فرض و مدیریت خطاها برای این پروژه مرجع مفیدی است.

### شروع سریع
1. آخرین نسخه پایدار Rust را با `rustup` نصب کنید.
2. مخزن را clone کرده و وارد پوشه پروژه شوید.
3. سرویس را با دستور زیر اجرا کنید:

```bash
cargo run --package chimera_server_app -- --config path/to/config.json5
```

4. برای hot reload می‌توانید از `start.sh` یا `start_server.ps1` استفاده کنید؛ قبل از اجرا بهتر است
   فرضیات آن‌ها درباره محیط را بررسی کنید.

### ابزار CLI
`chimera_cli` یک باینری کمکی به نام `chimera-cli` ارائه می‌کند تا تجربه‌ای مشابه
`xray x25519` فراهم شود. از ریشه workspace این دستور را اجرا کنید:

```bash
cargo run -p chimera_cli -- x25519 --count 1 --format base64
```

این دستور جفت کلید خصوصی/عمومی را با همان ترتیب xray-core چاپ می‌کند و از خروجی `base64` و
`hex` پشتیبانی می‌کند.

### پیکربندی
- فایل‌های پیکربندی از ساختار xray-core پیروی می‌کنند و در حال حاضر تمرکز اصلی روی آرایه
  `inbounds` و تنظیمات مربوط به پروتکل و transport است.
- parserها تلاش می‌کنند نام فیلدها و مقدارهای پیش‌فرض upstream را حفظ کنند تا پیکربندی‌های موجود
  xray-core با حداقل تغییر قابل استفاده باشند.
- در حال حاضر `json5` فرمت پیشنهادی است و پوشه `examples/` چند نمونه آماده در اختیار شما می‌گذارد.

### نمونه inbound
```json
{
  "inbounds": [
    {
      "tag": "vmess-tcp",
      "protocol": "vmess",
      "listen": "0.0.0.0",
      "port": 10086,
      "settings": {
        "clients": [
          {
            "id": "YOUR-UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp"
      }
    }
  ]
}
```

### نمونه‌های پیکربندی
- `examples/01-api.json5`
- `examples/02_trojan_ws_tls_30919.json5`
- `examples/03_vless_ws_tls_36050.json5`
- `examples/04_vless_tcp_50584.json5`
- `examples/05_vless_ws_56321.json5`
- `examples/06-hysteria-43210.json5`

### دستورات توسعه
```bash
cargo build --all-features
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

### نقشه راه
1. ادامه هم‌راستاسازی پروتکل‌های inbound پیاده‌سازی‌شده با جدیدترین رفتار xray-core، شامل
   فیلدهای اختیاری و جزئیات flow control.
2. ساخت مجموعه‌ای منظم از unit test و integration test و مقایسه رفتار با xray-core.
3. پس از پایدار شدن بخش inbound، تکمیل outbound، routing و policy برای رسیدن به سازگاری end-to-end.

## مشارکت

#### اگر در استفاده یا پیاده‌سازی مشکلی دیدید، Issue و PR با استقبال روبه‌رو می‌شوند.
#### حتی اگر تازه‌کار هستید، بهتر است ابتدا [wiki](https://mfsga.github.io/Proxy_WIKI/) را ببینید و بعد سؤال دقیق‌تری بپرسید. در صورت امکان پاسخ می‌دهم.
#### یکی از هدف‌های مهم این پروژه جذب توسعه‌دهندگان بیشتر برای مشارکت است.

## اگر این پروژه برای شما مفید بود، لطفاً به آن star بدهید

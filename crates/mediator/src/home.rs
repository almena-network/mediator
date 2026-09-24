//! The page a browser shows at the mediator's root: the icon, the name, and
//! what `/health` already makes public (status, version, DID). Nothing about
//! traffic: those numbers stay on the metrics listener. Below them, the
//! mediation invitation as a QR code for the wallet to scan.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// The app icon (384 px, shown at 128 px), served at [`ICON_PATH`].
pub const ICON: &[u8] = include_bytes!("../assets/icon.png");
pub const ICON_PATH: &str = "/icon.png";

/// The root page. Colours are the wallet's dark tokens with its blue accent,
/// the one the icon is drawn in; green and red carry the status only.
pub fn page(healthy: bool, version: &str, did: &str, invitation_url: &str) -> String {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let (state, label) = if healthy {
        ("ok", "Operational")
    } else {
        ("down", "Degraded")
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Almena Mediator</title>
<link rel="icon" type="image/png" href="{ICON_PATH}">
<style>
:root{{color-scheme:dark;--bg:#0f1013;--glow:rgba(47,111,237,.22);--surface:rgba(255,255,255,.06);--border:rgba(255,255,255,.1);--hover:rgba(255,255,255,.07);--text:#f4f4f6;--muted:rgba(244,244,246,.6);--ok:#3ddc84;--down:#ff6b5e}}
html,body{{height:100%;margin:0}}
body{{display:grid;place-items:center;background:radial-gradient(60rem 40rem at 50% 40%,var(--glow),transparent 70%),var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif}}
main{{display:flex;flex-direction:column;align-items:center;gap:1.5rem;padding:0 1rem;text-align:center;max-width:100%;box-sizing:border-box}}
img{{width:8rem;height:8rem}}
h1{{margin:0;font-size:clamp(1.75rem,6vw,2.5rem);font-weight:600;letter-spacing:-.02em}}
.status{{display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .85rem;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:.875rem}}
.status::before{{content:"";width:.5rem;height:.5rem;border-radius:50%;background:var(--c);box-shadow:0 0 .5rem var(--c)}}
.ok{{--c:var(--ok)}}.down{{--c:var(--down)}}
dl{{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.5rem 1rem;margin:0;font-size:.875rem;text-align:left;max-width:100%}}
dt{{color:var(--muted)}}dd{{margin:0;display:flex;align-items:center;gap:.5rem;min-width:0}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}}
button{{flex:none;padding:.2rem .6rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--muted);font:inherit;font-size:.75rem;cursor:pointer}}
button:hover{{background:var(--hover);color:var(--text)}}
figure{{margin:.5rem 0 0;display:flex;flex-direction:column;align-items:center;gap:.75rem}}
.qr{{width:16rem;max-width:80vw;padding:.75rem;border-radius:16px;background:#fff;box-sizing:border-box}}
.qr svg{{display:block;width:100%;height:auto}}
figcaption{{color:var(--muted);font-size:.875rem}}
</style></head>
<body><main>
<img src="{ICON_PATH}" alt="">
<h1>Almena Mediator</h1>
<span class="status {state}">{label}</span>
<dl>
<dt>Version</dt><dd><code>{version}</code></dd>
<dt>DID</dt><dd><code id="did">{did}</code><button type="button" id="copy">Copy</button></dd>
</dl>
<figure><a class="qr" href="{invitation_url}" aria-label="Mediation invitation">{qr}</a>
<figcaption>Scan with the Almena wallet to use this mediator.</figcaption></figure>
</main>
<script>
document.getElementById("copy").onclick=async e=>{{try{{await navigator.clipboard.writeText(document.getElementById("did").textContent);e.target.textContent="Copied"}}catch{{e.target.textContent="Failed"}}setTimeout(()=>e.target.textContent="Copy",1500)}};
</script>
</body></html>
"#,
        version = escape(version),
        did = escape(did),
        qr = qr_svg(invitation_url),
        invitation_url = escape(invitation_url),
    )
}

/// `text` as an inline SVG QR code, dark on white: what cameras read best.
/// Low error correction: a screen is not a scuffed label, and the ~400-byte
/// invitation URL then needs 69 modules instead of 77, which a phone reads
/// from further away. Empty if it does not fit, which the URL always does.
fn qr_svg(text: &str) -> String {
    QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map(|code| {
            code.render::<svg::Color>()
                .quiet_zone(false)
                .dark_color(svg::Color("#0f1013"))
                .light_color(svg::Color("#ffffff"))
                .build()
        })
        .map(|svg| {
            // Drop the XML prolog: the SVG is inlined in HTML.
            svg.find("<svg")
                .map_or(svg.clone(), |at| svg[at..].to_owned())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_shows_the_status_and_escapes_html() {
        const URL: &str = "https://x/oob?_oob=a&b";
        assert!(page(true, "1", "did:x", URL).contains("Operational"));
        assert!(page(false, "1", "did:x", URL).contains("Degraded"));
        let html = page(true, "<1>", "did:x", URL);
        assert!(html.contains("&lt;1&gt;"));
        assert!(html.contains("href=\"https://x/oob?_oob=a&amp;b\""));
        assert!(html.contains("<svg"));
        assert!(!html.contains("<?xml"));
    }
}

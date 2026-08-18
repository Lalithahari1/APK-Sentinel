import streamlit as st
import os, sys, json, hashlib, html, tempfile
from datetime import datetime

st.set_page_config(
    page_title="APK Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)

# Analyzer can be either ui/analyzer.py or project/apk_analyzer/analyzer.py
ANALYZER_CANDIDATES = [
    HERE,
    os.path.join(PROJECT_ROOT, "apk_analyzer"),
    os.path.join(PROJECT_ROOT, "ui"),
]
ANALYZER_FOLDER = next(
    (p for p in ANALYZER_CANDIDATES if os.path.exists(os.path.join(p, "analyzer.py"))),
    HERE,
)
if ANALYZER_FOLDER not in sys.path:
    sys.path.insert(0, ANALYZER_FOLDER)

try:
    from analyzer import analyze_apk, get_manifest
    ANALYZER_AVAILABLE = True
    ANALYZER_ERROR = ""
except Exception as exc:
    ANALYZER_AVAILABLE = False
    ANALYZER_ERROR = str(exc)

# AI/DNN runtime
AI_CANDIDATES = [
    os.path.join(PROJECT_ROOT, "src"),
    os.path.join(HERE, "src"),
]
AI_FOLDER = next((p for p in AI_CANDIDATES if os.path.isdir(p)), AI_CANDIDATES[0])
if AI_FOLDER not in sys.path:
    sys.path.insert(0, AI_FOLDER)

try:
    from ai_agent_runtime import run_dnn, generate_agent_summary
    AI_AVAILABLE = True
    AI_ERROR = ""
except Exception as exc:
    AI_AVAILABLE = False
    AI_ERROR = str(exc)

# User-approved visual assets. These are the exact banner + Android Security View
# images supplied in the current conversation.
HERO_CANDIDATES = [
    os.path.join(HERE, "assets", "apk_sentinel_banner.jpeg"),
    os.path.join(PROJECT_ROOT, "assets", "apk_sentinel_banner.jpeg"),
]
SECURITY_VIEW_CANDIDATES = [
    os.path.join(HERE, "assets", "android_security_view.png"),
    os.path.join(PROJECT_ROOT, "assets", "android_security_view.png"),
    os.path.join(HERE, "assets", "android_security_view.jpeg"),
    os.path.join(PROJECT_ROOT, "assets", "android_security_view.jpeg"),
]
HERO_IMAGE = next((p for p in HERO_CANDIDATES if os.path.exists(p)), None)
SECURITY_VIEW_IMAGE = next((p for p in SECURITY_VIEW_CANDIDATES if os.path.exists(p)), None)
SIDEBAR_ICON_CANDIDATES = [
    os.path.join(HERE, "assets", "android_sentinel_icon.png"),
    os.path.join(PROJECT_ROOT, "assets", "android_sentinel_icon.png"),
]
SIDEBAR_ICON = next((p for p in SIDEBAR_ICON_CANDIDATES if os.path.exists(p)), None)


def init_state():
    defaults = {
        "page": "Dashboard",
        "apk_queue": [],
        "current_result": None,
        "current_hash": "",
        "analysis_history": [],
        "current_ai": None,
        "uploader_version": 0,
        "ai_chat": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_state()


def esc(v):
    return html.escape(str(v if v is not None else ""))


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def clean_permission(v):
    return str(v or "").replace("android.permission.", "").strip()


def risk_level(score):
    score = int(score or 0)
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def level_for_ui(level):
    x = str(level or "").upper()
    return x if x in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW"


def signals(result):
    raw = result.get("risk_signal_details", []) or result.get("suspicious_permissions", []) or []
    if isinstance(raw, dict):
        raw = list(raw.values())
    return raw


def permission_categories(result):
    cats = result.get("permission_categories", {}) or {}
    return (
        cats.get("common", []) or [],
        cats.get("security_relevant", []) or [],
        cats.get("high_concern", []) or [],
        cats.get("other", []) or [],
    )


def component_count(result):
    return sum(
        len(result.get(k, []) or [])
        for k in ("activities", "services", "receivers", "providers")
    )


def add_history(result, digest):
    entry = {
        "apk_name": result.get("apk_name", "Unknown APK"),
        "risk_score": int(result.get("risk_score", 0) or 0),
        "risk_level": risk_level(result.get("risk_score", 0)),
        "permissions": len(result.get("permissions", []) or []),
        "components": component_count(result),
        "signals": len(signals(result)),
        "sha256": digest,
        "timestamp": datetime.now().strftime("%d %b %Y  %H:%M"),
    }
    st.session_state.analysis_history = [
        x for x in st.session_state.analysis_history if x.get("sha256") != digest
    ]
    st.session_state.analysis_history.append(entry)
    st.session_state.analysis_history = st.session_state.analysis_history[-50:]


def run_analysis(file_name, data):
    if not ANALYZER_AVAILABLE:
        raise RuntimeError(f"Analyzer could not be loaded: {ANALYZER_ERROR}")

    digest = sha256_bytes(data)
    temp_path = os.path.join(tempfile.gettempdir(), f"apk_sentinel_{digest[:12]}.apk")
    with open(temp_path, "wb") as f:
        f.write(data)

    try:
        result = analyze_apk(temp_path)
        if not isinstance(result, dict):
            raise ValueError("Analyzer returned an invalid result.")
        result["apk_name"] = file_name
        result["uploaded_file_hash"] = digest
        result["uploaded_file_size"] = len(data)

        # The score is the single source of truth for the displayed risk band.
        # This prevents stale/inconsistent analyzer labels (e.g. 8/100 + MEDIUM)
        # from overriding the dashboard scale.
        result["risk_level"] = risk_level(result.get("risk_score", 0))

        # Run the DNN only after static analysis has produced the feature evidence.
        ai = None
        if AI_AVAILABLE:
            try:
                manifest = get_manifest(temp_path) if "get_manifest" in globals() else ""
                ai = run_dnn(result, manifest or "")
            except Exception as exc:
                ai = {
                    "verdict": "UNAVAILABLE",
                    "malware_probability_percent": 0,
                    "confidence_percent": 0,
                    "model": "Final DNN",
                    "error": str(exc),
                    "feature_info": {},
                    "reasons": [],
                    "recommendation": "DNN inference could not be completed. Static analysis is still available.",
                }

        st.session_state.current_result = result
        st.session_state.current_hash = digest
        st.session_state.current_ai = ai
        st.session_state.ai_chat = []
        add_history(result, digest)
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass


# ---------------- CSS: the preferred WOW dashboard
# ----------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root{
 --bg:#030817; --panel:#07112d; --panel2:#09183c;
 --line:#182d66; --purple:#8a3ffc; --pink:#ff39d0;
 --cyan:#26b9ff; --blue:#2f7cff; --green:#22d98a;
 --yellow:#ffbd32; --red:#ff4f72; --text:#f5f7ff; --muted:#7f99cc;
}
*{font-family:Inter,sans-serif}
.stApp{
 background:
 radial-gradient(circle at 15% 0%,rgba(71,32,184,.28),transparent 30%),
 radial-gradient(circle at 90% 15%,rgba(155,24,193,.17),transparent 28%),
 linear-gradient(135deg,#020614 0%,#04102a 52%,#030817 100%);
 color:var(--text);
}
.block-container{max-width:1500px;padding:14px 24px 40px}
#MainMenu,footer{visibility:hidden}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{
 background:linear-gradient(180deg,#050d24,#020918);
 border-right:1px solid #122657;
}
[data-testid="stSidebar"]>div{padding-top:18px}
.sidebar-logo{
 text-align:center;padding:12px 10px 22px;border-bottom:1px solid #122657;margin-bottom:18px
}
.sidebar-android-icon{
 width:86px;height:86px;object-fit:contain;margin:0 auto 8px;display:block;
 border-radius:24px;filter:drop-shadow(0 0 18px rgba(64,132,255,.35));
}
.logo-shield{
 width:78px;height:78px;margin:auto;border-radius:24px;
 display:flex;align-items:center;justify-content:center;
 background:radial-gradient(circle,#142f72,#080e28);
 border:1px solid #3158bd;box-shadow:0 0 35px rgba(75,66,255,.35);
 font-size:42px
}
.logo-title{font-size:24px;font-weight:800;margin-top:12px}
.logo-sub{font-size:11px;color:#7292cf;letter-spacing:.7px;line-height:1.5}
.side-heading{color:#5f83c8;font-size:11px;font-weight:700;letter-spacing:1.4px;margin:18px 8px 8px}
.stButton>button{
 border-radius:11px!important; border:1px solid #18316f!important;
 background:rgba(7,19,51,.7)!important; color:#e7efff!important;
 font-weight:600!important; min-height:42px;
}
.stButton>button:hover{border-color:#7644ff!important;background:rgba(75,34,150,.4)!important}
.side-status{
 margin-top:25px;padding:15px;border:1px solid #122b62;border-radius:15px;
 background:rgba(8,24,58,.8)
}
.green-dot{color:#25df8d}
.status-small{font-size:10px;color:#7692c3;margin-top:3px}

.top-hero{
 height:120px;border-radius:18px;overflow:hidden;position:relative;
 border:1px solid #8a36ff;box-shadow:0 0 35px rgba(111,43,255,.25);
 background:
 linear-gradient(90deg,rgba(7,10,40,.85),rgba(14,6,48,.28)),
 radial-gradient(circle at 75% 40%,rgba(230,33,255,.35),transparent 25%),
 linear-gradient(90deg,#0b1538,#160a38 55%,#09193e);
 margin-bottom:22px;
}
.top-hero img{width:100%;height:100%;object-fit:cover;opacity:.72}
.hero-fallback{height:100%;display:flex;align-items:center;padding:0 9%;gap:25px}
.hero-mark{font-size:58px;filter:drop-shadow(0 0 16px #7548ff)}
.hero-name{font-size:46px;font-weight:800;letter-spacing:-2px}
.hero-name span{color:#9e57ff}
.hero-caption{color:#75a0e2;font-size:16px;margin-top:3px}
.hero-right{margin-left:auto;margin-right:4%;font-size:15px;color:white}

.page-row{display:flex;align-items:center;justify-content:space-between;margin:6px 0 18px}
.page-title{font-size:32px;font-weight:800}
.page-title .pulse{color:#6d6dff;margin-right:10px}
.page-sub{color:#6e91ca;font-size:12px;margin-top:3px}
.clock{border:1px solid #16326d;border-radius:20px;padding:11px 16px;color:#b7c9ee;font-size:11px;background:rgba(5,18,48,.55)}
.ready{display:inline-block;margin-left:10px;color:#20e28c;border:1px solid #145b4b;background:#08261f;padding:8px 12px;border-radius:18px}

.card{
 border:1px solid #19347a;border-radius:15px;
 background:linear-gradient(145deg,rgba(7,19,51,.96),rgba(4,11,30,.96));
 box-shadow:inset 0 1px rgba(255,255,255,.025),0 18px 50px rgba(0,0,0,.18);
}
.card-pad{padding:20px}
.card-title{font-size:16px;font-weight:750}
.card-title .cyan{color:#7ddaff}
.card-sub{font-size:10px;color:#6485bb;margin-top:5px}
.badge{
 display:inline-block;border:1px solid #173a78;border-radius:14px;padding:7px 12px;
 font-size:9px;color:#6dc6ff;background:#071b43;margin-left:6px
}
.badge.green{color:#6af2b3;border-color:#145c4a;background:#062b22}
.badge.yellow{color:#ffcb4f;border-color:#684c12;background:#2a2106}

.analysis-card{min-height:300px}
.analysis-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.app-row{display:flex;align-items:center;gap:16px}
.apk-icon{
 width:62px;height:62px;border-radius:12px;display:flex;align-items:center;justify-content:center;
 background:linear-gradient(145deg,#3a18a7,#7427ef);border:1px solid #8c47ff;
 font-size:32px;box-shadow:0 0 25px rgba(105,49,255,.3)
}
.app-name{font-size:25px;font-weight:800}
.package{font-size:12px;color:#7794c7;margin-top:4px}
.complete{margin-top:9px;display:inline-block;padding:6px 10px;border-radius:15px;color:#31e99a;background:#063a2c;border:1px solid #0d7859;font-size:10px}
.info-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.info-box{border:1px solid #142e69;border-radius:10px;padding:13px;background:rgba(4,14,38,.65)}
.info-label{font-size:10px;color:#6786bc}.info-value{font-size:13px;font-weight:700;margin-top:7px}
.hash{margin-top:12px;border:1px solid #142e69;border-radius:10px;padding:12px;font-size:10px;color:#83b8f1;word-break:break-all}

.security-view{height:300px;padding:14px}
.security-art{
 height:210px;border-radius:15px;border:1px solid #4e29bc;overflow:hidden;
 background:
 radial-gradient(circle at 52% 58%,rgba(245,31,219,.35),transparent 25%),
 radial-gradient(circle at 50% 90%,rgba(31,109,255,.4),transparent 40%),
 linear-gradient(135deg,#090b2a,#13073b 55%,#061a3b);
 display:flex;align-items:center;justify-content:center;position:relative
}
.phone{
 width:110px;height:180px;border-radius:20px;border:4px solid #2e64ff;
 background:linear-gradient(145deg,#111b46,#07132e);
 box-shadow:0 0 35px #9c2cff;display:flex;align-items:center;justify-content:center;
 font-size:55px;position:relative;z-index:2
}
.threat-icon{position:absolute;font-size:28px;color:#ff38d1}
.t1{left:30px;top:35px}.t2{right:28px;top:50px}.t3{left:28px;bottom:30px}.t4{right:35px;bottom:28px}
.risk-ring{
 position:absolute;right:18px;top:25px;width:92px;height:92px;border-radius:50%;
 background:conic-gradient(#ffbd32 0 20%,#162657 20% 100%);
 display:flex;align-items:center;justify-content:center
}
.risk-ring:after{content:"";width:70px;height:70px;border-radius:50%;background:#07112e}
.risk-text{position:absolute;z-index:4;text-align:center;font-size:19px;font-weight:800}.risk-text small{display:block;font-size:7px;color:#ffbd32}

.metric-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:14px}
.metric-card{padding:18px;border:1px solid #19347a;border-radius:15px;background:linear-gradient(145deg,#081536,#040c25);min-height:105px}
.metric-icon{font-size:24px}.metric-label{font-size:13px;color:#7ec9f7;margin-top:8px}.metric-value{font-size:32px;font-weight:800;margin-top:8px}.metric-note{font-size:10px;color:#6485b7}
.metric-value .unit{font-size:16px;color:#d9e4ff}

.lower-grid{display:grid;grid-template-columns:1.25fr .95fr .95fr;gap:14px;margin-top:14px}
.assessment{padding:18px}
.alert{
 border:1px solid #735018;background:linear-gradient(90deg,#34250b,#231a08);
 border-radius:10px;padding:16px;display:flex;align-items:center;gap:15px
}
.alert-icon{font-size:30px}.alert-title{font-size:17px;color:#ffc42e;font-weight:800}.alert-sub{font-size:10px;color:#a68b54;margin-top:4px}
.risk-scale{margin-top:18px}
.scale-bar{height:10px;border-radius:10px;background:linear-gradient(90deg,#20c878 0 25%,#ffbd32 25% 50%,#ff653f 50% 75%,#d91e52 75%);position:relative}
.scale-dot{position:absolute;width:15px;height:15px;border-radius:50%;background:white;border:3px solid #ffbd32;top:-2px;left:20%;box-shadow:0 0 10px #ffbd32}
.scale-labels{display:flex;justify-content:space-between;font-size:9px;color:#6684b9;margin-top:7px}

.donut-wrap{display:flex;align-items:center;gap:22px;min-height:170px}
.donut{
 width:130px;height:130px;border-radius:50%;
 background:conic-gradient(#22d98a 0 33%,#24aaf0 33% 66%,#f13f65 66% 83%,#8c43f5 83% 100%);
 display:flex;align-items:center;justify-content:center
}
.donut:after{content:"";width:86px;height:86px;border-radius:50%;background:#07112d}
.donut-center{position:absolute;text-align:center;font-size:21px;font-weight:800}.donut-center small{display:block;font-size:8px;color:#6f8fc6}
.legend{font-size:10px;color:#c0d0ee}.legend div{margin:9px 0}.dotc{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:7px}

.insight{font-size:11px;padding:9px 0;border-bottom:1px solid #13285d}.insight:last-child{border-bottom:0}.ok{color:#20db91}.warn{color:#ffca35}.info{color:#37b9ff}.insight small{display:block;color:#5e7bad;margin:4px 0 0 19px}

.pipeline{margin-top:14px;padding:18px;border:1px solid #19347a;border-radius:15px;background:#050e26}
.pipeline-title{font-size:15px;font-weight:750;margin-bottom:15px}
.steps{display:flex;align-items:center;justify-content:space-between;gap:4px}
.step{text-align:center;min-width:90px}.step-circle{width:28px;height:28px;border-radius:50%;margin:auto;background:#0a3b2e;border:1px solid #22d98a;color:#23e09a;display:flex;align-items:center;justify-content:center;font-size:12px}
.step.active .step-circle{background:#341078;border-color:#a14cff;color:#c17cff;box-shadow:0 0 18px rgba(160,76,255,.5)}
.step-label{font-size:9px;color:#7591c1;margin-top:7px}
.arrow{color:#5574aa}

.ai-panel{
 margin-top:14px;border:1px solid #5b32b9;border-radius:15px;
 background:linear-gradient(145deg,rgba(18,12,52,.98),rgba(5,12,34,.98));
 box-shadow:0 0 30px rgba(102,43,255,.12)
}
.ai-head{display:flex;justify-content:space-between;align-items:center;padding:17px 20px;border-bottom:1px solid #273168}
.ai-title{font-size:16px;font-weight:800}.ai-title span{color:#a45cff}
.ai-body{padding:18px}
.ai-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}
.ai-verdict{border:1px solid #124e43;background:#061f1a;border-radius:12px;padding:18px}
.ai-verdict.malware{border-color:#713048;background:#250b18}
.verdict{font-size:26px;font-weight:800;color:#25e19a}.malware .verdict{color:#ff6282}
.ai-number{font-size:34px;font-weight:800;margin-top:5px}
.ai-muted{font-size:10px;color:#6e8ab9}
.ai-list{border:1px solid #1b3470;border-radius:12px;padding:15px}
.ai-list h4{margin:0 0 9px;font-size:12px}.ai-list div{font-size:10px;color:#91a8d2;padding:6px 0;border-bottom:1px solid #122656}.ai-list div:last-child{border:0}
.agent-box{margin-top:14px;border:1px solid #233e7b;border-radius:12px;padding:15px;background:rgba(5,17,43,.8);font-size:11px;color:#9eb4dc;line-height:1.7}
.agent-box strong{color:#d7e4ff}
.ai-chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.ai-chip{border:1px solid #493080;border-radius:14px;padding:5px 9px;color:#c4a8ff;background:#150e30;font-size:9px}

.ai-chat{margin-top:14px;border:1px solid #243d7d;border-radius:15px;background:linear-gradient(145deg,#071534,#040c24);padding:18px}
.ai-chat-title{font-size:14px;font-weight:800;color:#eef4ff}.ai-chat-sub{font-size:10px;color:#6f8cc0;margin-top:4px}
.quick-questions{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 8px}
.chat-bubble{padding:11px 13px;border-radius:12px;margin-top:8px;font-size:11px;line-height:1.6;border:1px solid #1c356f}
.chat-user{background:#111e49;color:#c9dcff;margin-left:12%}.chat-agent{background:#071d29;color:#a9e8d2;margin-right:12%;border-color:#175b53}.chat-agent b{color:#43e4a7}
.chat-input-wrap{margin-top:12px}
.upload{
 border:1px dashed #6542c6;border-radius:14px;padding:18px;background:rgba(7,17,44,.8)
}
[data-testid="stFileUploader"]{background:transparent!important;border:0!important;padding:0!important}
[data-testid="stFileUploaderDropzone"]{background:#071536!important;border:1px dashed #29478d!important}
[data-testid="stFileUploaderDropzone"] *{color:#aac2eb!important}
.queue-item{padding:12px;border-bottom:1px solid #14285c}.queue-item:last-child{border-bottom:0}

.exact-banner{height:145px;background:#02030c}
.top-hero.exact-banner img{opacity:1;object-fit:cover;object-position:center;width:100%;height:100%}
.security-view{height:auto;min-height:390px;padding:14px}
.security-view-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.risk-mini{display:flex;flex-direction:column;align-items:flex-end;color:#ffca38;font-size:15px}.risk-mini span{font-size:8px;margin-top:3px;color:#8ba2cf;letter-spacing:.7px}
.security-image-wrap{height:285px;border-radius:14px;overflow:hidden;border:1px solid #4a2bb4;background:#030616;display:flex;align-items:center;justify-content:center;position:relative}
.risk-orb{
 position:absolute;right:14px;top:14px;width:92px;height:92px;border-radius:50%;
 background:conic-gradient(#ffbd32 0 var(--risk-pct),#17245b var(--risk-pct) 100%);
 display:flex;align-items:center;justify-content:center;z-index:5;
 box-shadow:0 0 25px rgba(255,189,50,.25);
}
.risk-orb:after{content:"";position:absolute;width:68px;height:68px;border-radius:50%;background:#050c25;border:1px solid #2b3d83}
.risk-orb-content{position:relative;z-index:6;text-align:center;color:#fff;font-weight:800;font-size:18px}
.risk-orb-content small{display:block;font-size:7px;color:#ffca38;letter-spacing:.5px;margin-top:2px}
.detail-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:11px}
.detail-table th{text-align:left;color:#77a0df;border-bottom:1px solid #1b3470;padding:9px}
.detail-table td{color:#d9e5ff;border-bottom:1px solid #102556;padding:9px;vertical-align:top}
.detail-chip{display:inline-block;padding:5px 8px;margin:3px;border-radius:12px;border:1px solid #203b7d;background:#08183b;color:#9ec6ff;font-size:9px}
.detail-chip.high{border-color:#7a3a4b;background:#2a0d1b;color:#ff9bb0}
.detail-chip.warn{border-color:#755a1b;background:#2c2208;color:#ffd56a}
.security-view-image{display:block;width:100%;height:100%;object-fit:contain;object-position:center;background:#030616}
.security-art-fallback{height:100%;display:flex;align-items:center;justify-content:center;color:#a85cff;font-size:55px;flex-direction:column}.security-art-fallback span{font-size:11px;color:#7e9bd0;margin-top:8px}
.security-view-footer{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:10px}.security-view-footer span{border:1px solid #142d68;border-radius:9px;padding:8px;color:#6f8dc1;font-size:9px}.security-view-footer b{color:#dce7ff;margin-left:3px}
@media(max-width:1100px){
 .lower-grid,.ai-grid{grid-template-columns:1fr}
 .metric-row{grid-template-columns:1fr 1fr}
}
@media(max-width:700px){
 .metric-row,.info-grid{grid-template-columns:1fr}
 .top-hero{height:150px}.hero-name{font-size:30px}
 .steps{overflow-x:auto;justify-content:flex-start}
}
</style>
""", unsafe_allow_html=True)



def _image_data_uri(path):
    if not path or not os.path.exists(path):
        return ""
    import base64
    ext = os.path.splitext(path)[1].lower()
    mime = "image/jpeg" if ext in {".jpg", ".jpeg"} else "image/png"
    with open(path, "rb") as f:
        return f"data:{mime};base64," + base64.b64encode(f.read()).decode()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    icon_uri = _image_data_uri(SIDEBAR_ICON) if SIDEBAR_ICON else ""
    icon_html = (
        f'<img class="sidebar-android-icon" src="{icon_uri}" alt="Android security icon">'
        if icon_uri else '<div class="logo-shield">🛡️</div>'
    )
    st.markdown(f"""
    <div class="sidebar-logo">
      {icon_html}
      <div class="logo-title">APK Sentinel</div>
      <div class="logo-sub">ANDROID APK SECURITY<br>INTELLIGENCE</div>
    </div>
    <div class="side-heading">WORKSPACE</div>
    """, unsafe_allow_html=True)

    items = [
        ("⌂", "Dashboard"),
        ("⌕", "Analyze APK"),
        ("◈", "Security Details"),
        ("◷", "History"),
        ("▣", "Reports"),
        ("⚙", "Settings"),
    ]
    for icon, label in items:
        if st.button(f"{icon}   {label}", key=f"side_{label}", use_container_width=True):
            st.session_state.page = label
            st.rerun()

    st.markdown("""
    <div class="side-status">
      <b><span class="green-dot">●</span> Analyzer Ready</b>
      <div class="status-small">Local static APK analysis</div>
    </div>
    """, unsafe_allow_html=True)


def top_hero():
    """Legacy compatibility hook. The preferred UI intentionally has no top banner."""
    return


def page_header():
    now = datetime.now()
    st.markdown(f"""
    <div class="page-row">
      <div>
        <div class="page-title"><span class="pulse">〽</span>Dashboard</div>
        <div class="page-sub">Android APK security intelligence, risk assessment and threat indicators.</div>
      </div>
      <div>
        <span class="clock">▣ &nbsp; {now.strftime("%d %b %Y")} &nbsp;&nbsp; {now.strftime("%H:%M")}</span>
        <span class="ready">● &nbsp; System Online</span>
      </div>
    </div>
    """, unsafe_allow_html=True)




def security_view(result):
    score = int((result or {}).get("risk_score", 0) or 0)
    level = risk_level(score)
    sigs = len(signals(result or {}))
    img = _image_data_uri(SECURITY_VIEW_IMAGE)
    if img:
        art = f'<img class="security-view-image" src="{img}" alt="Android Security View">'
    else:
        art = '<div class="security-art-fallback">🛡️<span>Android Security View</span></div>'
    st.markdown(f"""
    <div class="card security-view">
      <div class="security-view-head">
        <div>
          <div class="card-title">🛡️ &nbsp; Android Security View</div>
          <div class="card-sub">Visual representation of APK security and risk analysis.</div>
        </div>
        <div class="risk-mini"><b>{score}/100</b><span>{level} RISK</span></div>
      </div>
      <div class="security-image-wrap">
        {art}
        <div class="risk-orb" style="--risk-pct:{max(0,min(score,100))}%">
          <div class="risk-orb-content">{score}<small>/ 100<br>{esc(level)} RISK</small></div>
        </div>
      </div>
      <div class="security-view-footer">
        <span>🔐 Permissions <b>{len((result or {}).get('permissions', []) or [])}</b></span>
        <span>⚙ Components <b>{component_count(result or {})}</b></span>
        <span>⚠ Risk Signals <b>{sigs}</b></span>
      </div>
    </div>
    """, unsafe_allow_html=True)



def list_field(result, *keys):
    """Return the first non-empty list-like field found under any of the supplied keys."""
    for key in keys:
        value = result.get(key)
        if value:
            if isinstance(value, dict):
                return list(value.values())
            if isinstance(value, (list, tuple, set)):
                return list(value)
            return [value]
    return []


def network_urls(result):
    return list_field(
        result,
        "urls", "url_indicators", "network_urls", "network_indicators",
        "network_domains", "domains", "domain_indicators", "network_domains_indicators",
    )


def component_items(result, key):
    values = list_field(result, key)
    return values


def security_details_page():
    result = st.session_state.current_result
    st.markdown('<div class="page-title"><span class="pulse">◈</span> Security Details</div><div class="page-sub">Detailed static evidence extracted from the analyzed APK.</div>', unsafe_allow_html=True)
    if not result:
        st.markdown('<div class="card card-pad" style="margin-top:16px">Analyze an APK first. Permissions, risk factors, URLs, indicators and components will appear here.</div>', unsafe_allow_html=True)
        return

    perms = result.get("permissions", []) or []
    common, security, high, other = permission_categories(result)
    sigs = signals(result)
    urls = network_urls(result)
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔐 Permissions", "⚠ Risk Factors", "🌐 URLs & Indicators", "⚙ Components", "📋 Raw Evidence"
    ])

    with tab1:
        st.markdown(f'<div class="card card-pad"><div class="card-title">Permissions <span class="badge">{len(perms)} total</span></div>', unsafe_allow_html=True)
        groups = [
            ("Common", common, ""),
            ("Security-Relevant", security, "warn"),
            ("High-Concern", high, "high"),
            ("Other", other, ""),
        ]
        for title, vals, cls in groups:
            st.markdown(f'<h4 style="margin:18px 0 6px;color:#8fcaff">{title} <span class="badge">{len(vals)}</span></h4>', unsafe_allow_html=True)
            if vals:
                st.markdown(" ".join(f'<span class="detail-chip {cls}">{esc(clean_permission(v))}</span>' for v in vals), unsafe_allow_html=True)
            else:
                st.markdown('<span class="card-sub">None detected.</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown(f'<div class="card card-pad"><div class="card-title">Risk Factors / Security Signals <span class="badge">{len(sigs)}</span></div>', unsafe_allow_html=True)
        if sigs:
            rows=[]
            for item in sigs:
                if isinstance(item, dict):
                    name=item.get("name") or item.get("signal") or item.get("permission") or "Security signal"
                    desc=item.get("description") or item.get("reason") or item.get("detail") or ""
                else:
                    name=str(item); desc=""
                rows.append(f'<tr><td><b>{esc(name)}</b></td><td>{esc(desc)}</td></tr>')
            st.markdown('<table class="detail-table"><thead><tr><th>Risk factor</th><th>Why it matters</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="card-sub">No risk factors were returned by the static analyzer.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab3:
        st.markdown(f'<div class="card card-pad"><div class="card-title">Network Indicators <span class="badge">{len(urls)}</span></div>', unsafe_allow_html=True)
        if urls:
            rows=[]
            for item in urls:
                if isinstance(item, dict):
                    value=item.get("url") or item.get("domain") or item.get("indicator") or item.get("value") or str(item)
                    kind=item.get("type") or item.get("kind") or "network indicator"
                else:
                    value=str(item); kind="network indicator"
                rows.append(f'<tr><td><b>{esc(value)}</b></td><td>{esc(kind)}</td></tr>')
            st.markdown('<table class="detail-table"><thead><tr><th>URL / Domain / Indicator</th><th>Type</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="card-sub">No URL/domain/network indicators were returned for this APK.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.markdown('<div class="card card-pad"><div class="card-title">Android Components</div>', unsafe_allow_html=True)
        for key, label in [("activities","Activities"),("services","Services"),("receivers","Broadcast Receivers"),("providers","Providers")]:
            vals=component_items(result,key)
            st.markdown(f'<h4 style="margin:18px 0 6px;color:#8fcaff">{label} <span class="badge">{len(vals)}</span></h4>', unsafe_allow_html=True)
            if vals:
                st.markdown(" ".join(f'<span class="detail-chip">{esc(v.get("name") if isinstance(v,dict) else v)}</span>' for v in vals), unsafe_allow_html=True)
            else:
                st.markdown('<span class="card-sub">None detected.</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab5:
        st.json(result)


def answer_ai_question(question, result, ai):
    """Small, transparent local AI-agent layer for project demonstrations.

    It answers common mentor/user questions from the actual current APK result
    and DNN output. It does not pretend to perform dynamic analysis or invent
    evidence that the analyzer did not extract.
    """
    q = (question or "").strip().lower()
    if not result:
        return "Please analyze an APK first. Once an APK is analyzed, I can explain its risk score, permissions, components, signals and DNN result."

    perms = result.get("permissions", []) or []
    common, sec, high, other = permission_categories(result)
    sigs = signals(result)
    score = int(result.get("risk_score", 0) or 0)
    level = risk_level(score)
    services = result.get("services", []) or []
    receivers = result.get("receivers", []) or []
    activities = result.get("activities", []) or []
    providers = result.get("providers", []) or []
    ai_verdict = (ai or {}).get("verdict", "UNAVAILABLE")
    prob = float((ai or {}).get("malware_probability_percent", 0) or 0)
    conf = float((ai or {}).get("confidence_percent", 0) or 0)

    if any(k in q for k in ["risk score", "score", "why risk", "risk level"]):
        return f"The static risk score is {score}/100 ({level} risk). It is based on security-related permissions and analyzer signals; it is not proof that the APK is malware. {len(sigs)} risk signal(s) contributed to the current assessment."
    if any(k in q for k in ["malware", "dnn", "ai result", "prediction", "prediction"]):
        return f"The Final DNN currently predicts {ai_verdict} with a malware probability of {prob:.2f}% and confidence of {conf:.2f}%. The model uses the extracted feature vector. Dynamic feature slots are not populated by runtime execution."
    if "permission" in q:
        names = [str(x).replace("android.permission.", "") for x in high[:8]]
        extra = ", ".join(names) if names else "none in the high-concern group"
        return f"The APK requests {len(perms)} permission(s): {len(common)} common, {len(sec)} security-relevant, {len(high)} high-concern and {len(other)} other. High-concern examples: {extra}."
    if any(k in q for k in ["component", "service", "receiver", "activity", "provider"]):
        return f"The analyzer found {len(activities)} activities, {len(services)} services, {len(receivers)} broadcast receivers and {len(providers)} providers. Services and boot/startup receivers are especially useful context when reviewing background behavior."
    if any(k in q for k in ["signal", "indicator", "threat"]):
        if not sigs:
            return "No security risk signals were returned by the static analyzer for this APK."
        names=[]
        for item in sigs[:8]:
            if isinstance(item, dict):
                names.append(str(item.get("name") or item.get("signal") or item.get("permission") or "signal"))
            else:
                names.append(str(item))
        return f"There are {len(sigs)} risk signals. Examples include: {', '.join(names)}. These are indicators used for review and scoring, not automatic proof of malicious intent."
    if any(k in q for k in ["safe", "install", "should i install"]):
        return f"I would not label the APK simply safe or malicious from static analysis alone. The current result is {level} risk with a DNN verdict of {ai_verdict}. Verify the source and signature and use controlled dynamic analysis if you need stronger evidence."
    if any(k in q for k in ["explain", "summary", "overall", "what do you think"]):
        rec=(ai or {}).get("recommendation", "Review the static evidence before installation.")
        return f"Overall: {level} risk, {len(perms)} permissions, {len(sigs)} risk signals and {component_count(result)} Android components. DNN: {ai_verdict} ({prob:.2f}% malware probability). Recommendation: {rec}"
    return "I can explain the current APK's risk score, DNN prediction, permissions, components, risk signals, or whether the evidence suggests further review. Try a question such as 'Why is the risk score high?' or 'What did the DNN predict?'"


def dashboard():
    result = st.session_state.current_result
    ai = st.session_state.current_ai

    # Preferred clean dashboard: branding stays in the left sidebar.
    # Do not render a large banner above the dashboard.
    page_header()

    if result is None:
        # Same visual structure as the preferred dashboard, but with empty-state values.
        apk_name = "No APK analyzed"
        package = "Upload an APK to begin"
        version = "—"
        size = "—"
        digest = "—"
        score = 0
        level = "LOW"
        perms = []
        comps = 0
        sigs = []
    else:
        apk_name = result.get("apk_name", "Unknown APK")
        package = result.get("package_name") or result.get("package") or result.get("package_id") or "Package not returned"
        version = result.get("version_name") or result.get("version") or "—"
        size = f'{int(result.get("uploaded_file_size",0) or 0)/(1024*1024):.2f} MB'
        digest = result.get("uploaded_file_hash") or st.session_state.current_hash or "—"
        score = int(result.get("risk_score",0) or 0)
        level = risk_level(score)
        perms = result.get("permissions", []) or []
        comps = component_count(result)
        sigs = len(signals(result))

    left, right = st.columns([1.55, .95], gap="medium")

    with left:
        st.markdown(f"""
        <div class="card card-pad analysis-card">
          <div class="analysis-top">
            <div class="card-title">▣ &nbsp; <span class="cyan">Current Analysis</span></div>
            <div>
              <span class="badge">⚡ STATIC</span>
              <span class="badge">◈ NO INSTALL</span>
              <span class="badge">▣ LOCAL</span>
            </div>
          </div>
          <div class="app-row">
            <div class="apk-icon">🤖<br><span style="font-size:10px">APK</span></div>
            <div>
              <div class="app-name">{esc(apk_name)}</div>
              <div class="package">{esc(package)}</div>
              {"<div class='complete'>✓ Analysis Complete</div>" if result else "<div class='complete' style='color:#8db2ed;background:#08183c;border-color:#193b78'>Waiting for APK</div>"}
            </div>
          </div>
          <div class="info-grid" style="margin-top:20px">
            <div class="info-box"><div class="info-label">Version</div><div class="info-value">{esc(version)}</div></div>
            <div class="info-box"><div class="info-label">Analysis Mode</div><div class="info-value">Static APK analysis</div></div>
            <div class="info-box"><div class="info-label">File Size</div><div class="info-value">{esc(size)}</div></div>
          </div>
          <div class="hash"><b>SHA-256</b>&nbsp;&nbsp; {esc(digest[:64])}</div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        security_view(result)

    # Four metric cards
    metric_data = [
        ("🎯", "Risk Score", f'{score} <span class="unit">/100</span>', level),
        ("🔐", "Permissions", str(len(perms)), "Total Permissions"),
        ("◈", "Components", str(comps), "Activities + Services"),
        ("⚠️", "Risk Signals", str(sigs), "Risk Indicators"),
    ]
    cols = st.columns(4)
    for col, (icon, label, value, note) in zip(cols, metric_data):
        with col:
            if label == "Risk Score":
                n = f'<div class="metric-value">{value}</div><div class="metric-note">{esc(note)} RISK</div>'
            else:
                n = f'<div class="metric-value">{value}</div><div class="metric-note">{esc(note)}</div>'
            st.markdown(
                f'<div class="metric-card"><div class="metric-icon">{icon}</div><div class="metric-label">{label}</div>{n}</div>',
                unsafe_allow_html=True,
            )

    # Lower dashboard cards
    common, security, high, other = permission_categories(result or {})
    c1, c2, c3 = st.columns([1.25, .95, .95], gap="medium")

    with c1:
        label = level
        color_title = {"LOW":"LOW RISK","MEDIUM":"MEDIUM RISK","HIGH":"HIGH RISK","CRITICAL":"CRITICAL RISK"}.get(label,label)
        st.markdown(f"""
        <div class="card assessment">
          <div class="card-title">🛡️ &nbsp; Security Assessment</div>
          <div class="alert">
            <div class="alert-icon">⚠️</div>
            <div><div class="alert-title">{color_title}</div>
            <div class="alert-sub">{"Some security indicators detected. Review recommended." if sigs else "No major security indicators detected by the static analyzer."}</div></div>
          </div>
          <div class="risk-scale">
            <div class="scale-bar"><div class="scale-dot" style="left:{min(score,99)}%"></div></div>
            <div class="scale-labels"><span>LOW<br>0–24</span><span>MEDIUM<br>25–49</span><span>HIGH<br>50–74</span><span>CRITICAL<br>75–100</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        total = max(1, len(perms))
        c_common = round(len(common)/total*100)
        c_sec = round(len(security)/total*100)
        c_high = round(len(high)/total*100)
        c_other = max(0,100-c_common-c_sec-c_high)
        st.markdown(f"""
        <div class="card card-pad">
          <div class="card-title">◈ &nbsp; Permission Distribution</div>
          <div class="donut-wrap">
            <div style="position:relative"><div class="donut"></div><div class="donut-center">{len(perms)}<small>Total</small></div></div>
            <div class="legend">
              <div><span class="dotc" style="background:#22d98a"></span>Common <b>{len(common)}</b> &nbsp; {c_common}%</div>
              <div><span class="dotc" style="background:#24aaf0"></span>Security Relevant <b>{len(security)}</b> &nbsp; {c_sec}%</div>
              <div><span class="dotc" style="background:#f13f65"></span>High Concern <b>{len(high)}</b> &nbsp; {c_high}%</div>
              <div><span class="dotc" style="background:#8c43f5"></span>Other <b>{len(other)}</b> &nbsp; {c_other}%</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="card card-pad">
          <div class="card-title">💡 &nbsp; Quick Insights</div>
          <div class="insight"><span class="ok">●</span> Static analysis only<small>No installation performed</small></div>
          <div class="insight"><span class="ok">●</span> APK verified locally<small>Hash calculated</small></div>
          <div class="insight"><span class="warn">▲</span> Review permissions<small>{len(high)} high-concern permission(s)</small></div>
          <div class="insight"><span class="info">●</span> {sigs} risk signals<small>Signals contributing to risk analysis</small></div>
        </div>
        """, unsafe_allow_html=True)

    # DNN + AI agent: added without changing the preferred dashboard structure.
    if result is not None:
        ai_verdict = (ai or {}).get("verdict", "UNAVAILABLE")
        prob = float((ai or {}).get("malware_probability_percent", 0) or 0)
        conf = float((ai or {}).get("confidence_percent", 0) or 0)
        fi = (ai or {}).get("feature_info", {}) or {}
        reasons = (ai or {}).get("reasons", []) or []
        important = (ai or {}).get("active_influential_features", []) or []
        recommendation = (ai or {}).get("recommendation", "")
        malware_class = "malware" if ai_verdict == "MALWARE" else ""

        if ai and "error" not in ai:
            ai_inner = f"""
            <div class="ai-grid">
              <div class="ai-verdict {malware_class}">
                <div class="ai-muted">ML MALWARE VERDICT</div>
                <div class="verdict">{"🔴 MALWARE" if ai_verdict=="MALWARE" else "🟢 BENIGN"}</div>
                <div class="ai-number">{prob:.2f}%</div>
                <div class="ai-muted">Malware probability &nbsp; • &nbsp; Confidence {conf:.2f}%</div>
                <div class="ai-chips">
                  <span class="ai-chip">🧠 Final DNN</span>
                  <span class="ai-chip">📐 {fi.get("total_features",0)} features</span>
                  <span class="ai-chip">🎚 threshold 50%</span>
                  <span class="ai-chip">🔎 {conf:.2f}% confidence</span>
                </div>
              </div>
              <div class="ai-list">
                <h4>🔬 Model-influencing features</h4>
                {''.join(f'<div>• {esc(x)}</div>' for x in important[:8]) if important else '<div>No active top-importance features were identified.</div>'}
              </div>
            </div>
            <div class="agent-box">
              <strong>🤖 AI Security Agent</strong><br>
              {" ".join(esc(x) for x in reasons) if reasons else "The agent found no additional static explanation."}<br><br>
              <strong>Recommendation:</strong> {esc(recommendation)}
            </div>
            <div class="agent-box"><strong>AI transparency:</strong> Static APK analysis is currently used. Dynamic feature slots are retained for model compatibility and are not populated by runtime execution.</div>
            """
        else:
            err = esc((ai or {}).get("error") or AI_ERROR or "AI runtime unavailable")
            ai_inner = f'<div class="agent-box"><strong>DNN / AI Agent unavailable:</strong> {err}<br>Static APK analysis remains fully available.</div>'

        st.markdown(f"""
        <div class="ai-panel">
          <div class="ai-head">
            <div class="ai-title">🤖 APK Sentinel <span>AI Security Agent</span></div>
            <div><span class="badge green">● DNN INFERENCE</span><span class="badge">340 FEATURES</span></div>
          </div>
          <div class="ai-body">{ai_inner}</div>
        </div>
        """, unsafe_allow_html=True)

    # Conversational AI stays on the Dashboard only and is collapsed by default
    # so the dashboard remains clean while still providing mentor/user Q&A.
    if result is not None:
        with st.expander("💬 Ask APK Sentinel AI Security Agent", expanded=False):
            st.caption("Ask a basic question or type your own doubt. Answers are grounded in the current static analysis and DNN result.")
            quick = [
                "Why is this APK risky?",
                "What did the DNN predict?",
                "Which permissions need attention?",
                "What components were found?",
            ]
            qcols = st.columns(4)
            for col, q in zip(qcols, quick):
                with col:
                    if st.button(q, key="quick_" + q, use_container_width=True):
                        ans = answer_ai_question(q, result, ai)
                        st.session_state.ai_chat.append(("user", q))
                        st.session_state.ai_chat.append(("agent", ans))
                        st.rerun()
            for who, msg in st.session_state.ai_chat[-8:]:
                if who == "user":
                    st.markdown(f'<div class="chat-bubble chat-user"><b>You:</b> {esc(msg)}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="chat-bubble chat-agent"><b>APK Sentinel AI:</b> {esc(msg)}</div>', unsafe_allow_html=True)
            with st.form("ai_chat_form", clear_on_submit=True):
                user_q = st.text_input("Ask your doubt", placeholder="e.g. Why did the risk score become high?", label_visibility="collapsed")
                submitted = st.form_submit_button("Send to AI Agent →", use_container_width=True)
            if submitted and user_q.strip():
                st.session_state.ai_chat.append(("user", user_q.strip()))
                st.session_state.ai_chat.append(("agent", answer_ai_question(user_q, result, ai)))
                st.rerun()


def analyzer_page():
    st.markdown('<div class="page-title">🔎 Analyze APK</div><div class="page-sub">Upload one or more Android APKs. They are analyzed locally and never installed.</div>', unsafe_allow_html=True)
    st.markdown('<div class="card card-pad upload">', unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Upload APK",
        type=["apk"],
        accept_multiple_files=True,
        key=f"uploader_{st.session_state.uploader_version}",
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if uploaded:
        for f in uploaded:
            data = f.getvalue()
            digest = sha256_bytes(data)
            if not any(x["sha256"] == digest for x in st.session_state.apk_queue):
                st.session_state.apk_queue.append({"name": f.name, "bytes": data, "size": len(data), "sha256": digest})

    if st.session_state.apk_queue:
        st.markdown('<div class="card card-pad" style="margin-top:14px"><div class="card-title">APK Queue</div>', unsafe_allow_html=True)
        for x in st.session_state.apk_queue:
            st.markdown(f'<div class="queue-item"><b>📦 {esc(x["name"])}</b><br><span class="card-sub">{x["size"]/(1024*1024):.2f} MB · SHA-256 {x["sha256"][:16]}…</span></div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        a,b = st.columns(2)
        with a:
            if st.button("🚀 ANALYZE APK", use_container_width=True):
                item = st.session_state.apk_queue[-1]
                with st.spinner("Running static analysis + DNN inference..."):
                    try:
                        run_analysis(item["name"], item["bytes"])
                        st.session_state.apk_queue = []
                        st.session_state.page = "Dashboard"
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))
        with b:
            if st.button("✕ CLEAR QUEUE", use_container_width=True):
                st.session_state.apk_queue = []
                st.rerun()


def history_page():
    st.markdown('<div class="page-title">◷ History</div><div class="page-sub">Completed APK analyses in this Streamlit session.</div>', unsafe_allow_html=True)
    for x in reversed(st.session_state.analysis_history):
        st.markdown(f"""
        <div class="card card-pad" style="margin-top:10px">
          <b>{esc(x["apk_name"])}</b> &nbsp; <span class="badge">{x["risk_level"]}</span>
          <div class="card-sub">Risk {x["risk_score"]}/100 · {x["permissions"]} permissions · {x["components"]} components · {x["signals"]} signals · {x["timestamp"]}</div>
        </div>
        """, unsafe_allow_html=True)
    if not st.session_state.analysis_history:
        st.markdown('<div class="card card-pad" style="margin-top:15px;color:#7190c4">No completed analyses yet.</div>', unsafe_allow_html=True)


def reports_page():
    st.markdown('<div class="page-title">▣ Reports</div><div class="page-sub">Export the analyzer and DNN assessment.</div>', unsafe_allow_html=True)
    if not st.session_state.current_result:
        st.markdown('<div class="card card-pad" style="margin-top:15px">Analyze an APK first.</div>', unsafe_allow_html=True)
        return
    payload = {
        "static_analysis": st.session_state.current_result,
        "dnn_ai_assessment": st.session_state.current_ai,
    }
    st.download_button(
        "⬇ Download Complete AI Security Assessment",
        json.dumps(payload, indent=2, default=str),
        file_name=f'{st.session_state.current_result.get("apk_name","apk").replace(" ","_")}_assessment.json',
        mime="application/json",
        use_container_width=True,
    )


def settings_page():
    st.markdown('<div class="page-title">⚙ Settings</div><div class="page-sub">APK Sentinel configuration and model status.</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="card card-pad" style="margin-top:15px">
      <b>Static Analyzer</b><br><span class="card-sub">{"READY" if ANALYZER_AVAILABLE else "ERROR: "+esc(ANALYZER_ERROR)}</span><br><br>
      <b>DNN / AI Agent</b><br><span class="card-sub">{"READY" if AI_AVAILABLE else "ERROR: "+esc(AI_ERROR)}</span><br><br>
      <b>Dashboard visuals</b><br><span class="card-sub">Dashboard uses the APK Sentinel color language, sidebar Android identity, and Android Security View artwork. The large top banner is intentionally disabled.</span>
    </div>
    """, unsafe_allow_html=True)


page = st.session_state.page
if page == "Dashboard":
    dashboard()
elif page == "Analyze APK":
    analyzer_page()
elif page == "Security Details":
    security_details_page()
elif page == "History":
    history_page()
elif page == "Reports":
    reports_page()
elif page == "Settings":
    settings_page()

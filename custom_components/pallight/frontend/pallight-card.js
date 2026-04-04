/**
 * Emulated PalLighting Color Wheel and control
 * Version: 7.1.0
 *
 * Installation:
 *   1. Copy to /config/www/pallight-card-v7.js
 *   2. Settings → Dashboards → Resources → delete old entry, add:
 *        URL:  /local/pallight-card-v7.js
 *        Type: JavaScript module
 *   3. Hard-refresh the browser (Ctrl+Shift+R)
 *
 * Card YAML:
 *   type: custom:pallight-card
 *   entity: light.pallight_living_room
 *   name: Pool
 *
 * Wheel colours (clock positions):
 *   12 = BLUE,  3 = GREEN,  6 = YELLOW,  9 = RED
 *   9→12 = smooth magenta/purple gradient (CSS interpolated, no hard line)
 *   6→9  = orange gradient (device APK colours)
 *
 * v7 additions:
 *   - MODE UP/DOWN cycles through built-in effects (Gradient, Strobe, Jump,
 *     Fade, Flash, Rainbow, Rainbow Strobe) via light.turn_on effect:
 *   - SPEED UP/DOWN sends brightness_step which the integration routes to
 *     effect speed when an effect is active (0x0000=fast, 0xFFFF=slow)
 *   - Status bar shows active effect name
 *   - Centre dot shows effect name text when in effect mode
 *   - Wheel handle parks at 12 o'clock and dims when effect is active
 *
 * v7.1 additions:
 *   - Entire card body (wheel + controls) fades to 35% opacity when light is
 *     off and becomes non-interactive; ON/OFF buttons remain fully active
 */

(() => {
  if (customElements.get("pallight-card")) return;

  const VERSION = "0.9.1";
  // Changelog:
  //   0.9.1  Streaming drag: sends colour every 50ms during drag (matching native app);
  //          tap-to-select sends immediately on touch-down
  //   0.9.0  Aligned to integration version. callService .catch() on all service
  //          calls, null-safe _wire(), inline style for off-state opacity
  //   7.1.0  Off-state opacity layer (body-wrap fades to 35% when light is off)
  //   7.0.0  MODE/SPEED buttons wired, effect name label, handle parks in effect
  //          mode, mode buttons highlight purple when effect active
  //   6.0.0  Initial colour wheel card
  const CX = 140, CY = 140, OUTER_R = 132, INNER_R = 70, HANDLE_R = 105;

  // Must match EFFECT_NAMES in const.py exactly (order defines cycle direction)
  const EFFECTS = [
    "Gradient", "Strobe", "Jump", "Fade", "Flash", "Rainbow", "Rainbow Strobe"
  ];
  // Speed step per button press — sent as brightness_step, integration converts
  // to device speed. 25/255 ≈ 10% per press.
  const SPEED_STEP = 25;
// fairly sure these are still wrong on the colour wheel - needs more work here !
const PAL_R = [
  0,6,6,6,12,12,18,18,18,24,30,30,30,36,36,42,42,48,
  48,48,54,60,60,60,66,66,72,78,78,78,85,85,91,91,91,97,
  103,103,109,109,109,115,121,121,121,121,127,133,133,133,139,139,145,151,
  151,151,157,157,163,163,163,170,176,176,182,182,182,188,194,194,194,200,
  200,206,212,212,212,212,218,224,224,224,230,230,236,236,236,242,248,248,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,249,243,238,232,226,221,215,209,
  204,198,192,187,181,175,170,164,158,153,147,141,135,130,124,119,113,107,
  101,96,90,84,79,73,67,62,56,50,45,39,33,28,22,16,11,5,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
];
const PAL_G = [
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,248,242,242,242,236,236,230,224,224,224,218,218,212,212,212,
  206,200,200,194,194,194,188,182,182,182,176,176,170,170,170,163,157,157,
  151,151,151,145,139,139,139,133,133,127,121,121,121,115,115,109,109,109,
  103,97,97,91,91,91,85,78,78,78,72,72,66,66,66,60,54,54,
  48,48,48,42,36,36,36,30,30,24,18,18,18,12,12,6,6,6,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,12,12,18,24,30,36,42,48,54,60,66,72,78,85,85,91,
  103,103,109,115,121,127,133,139,145,151,157,157,170,176,176,188,188,194,
  206,206,212,218,224,230,236,242,248,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
];
const PAL_B = [
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,5,11,16,22,28,34,39,45,51,56,62,67,73,79,85,90,96,
  102,107,113,119,124,130,135,141,147,152,158,164,170,175,181,187,192,198,
  203,209,215,221,226,232,238,243,249,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,248,248,242,230,230,224,218,212,
  206,200,194,188,182,176,176,163,157,157,145,145,139,127,127,121,115,109,
  103,97,91,85,85,72,72,66,54,54,48,42,36,30,24,18,12,6,
];
const HUE_TO_CANVAS = [
  180,177,177,175,172,171,171,169,166,166,165,162,160,160,159,156,156,154,
  151,151,150,147,147,145,144,141,141,139,136,136,135,133,130,130,129,126,
  126,124,123,123,120,118,118,115,114,111,111,109,108,108,105,103,100,100,
  99,97,97,94,93,93,90,88,88,87,84,84,82,79,78,78,74,73,
  73,71,68,68,67,64,62,62,61,58,58,56,53,53,52,50,50,47,
  46,42,42,41,38,38,36,35,32,32,30,27,27,26,24,24,21,20,
  17,17,15,13,13,10,9,9,6,4,1,1,0,359,359,358,357,356,
  356,355,354,354,353,352,352,350,350,349,349,347,347,345,345,344,344,343,
  342,341,341,340,339,339,337,337,336,336,334,334,332,332,331,331,329,329,
  329,328,327,326,326,325,324,324,323,322,322,321,319,319,318,318,316,316,
  315,314,314,313,312,312,311,310,309,309,308,306,306,305,305,305,303,303,
  301,301,300,300,298,298,297,297,296,295,295,294,293,292,292,291,290,290,
  288,288,287,287,285,284,284,283,282,282,281,280,279,279,278,277,277,276,
  275,275,274,272,272,270,270,269,268,268,267,266,265,265,264,263,262,262,
  261,260,259,259,258,257,256,256,255,254,253,253,252,251,250,250,249,248,
  247,247,246,245,244,244,243,242,241,241,240,239,238,238,237,236,235,235,
  234,233,232,232,231,230,229,229,228,227,226,226,225,224,224,223,222,221,
  221,220,219,218,218,217,216,215,215,214,213,212,212,211,210,209,209,208,
  207,206,206,205,204,203,203,202,201,200,200,199,198,197,197,196,195,194,
  194,193,192,191,191,190,189,188,188,187,186,185,185,184,183,182,182,181,
];

  // canvas angle (0=right/3 o'clock, 90=bottom/6, 180=left/9, 270=top/12)
  // → RGB colour to draw on the wheel
  function degToRgb(deg) {
    const i = ((Math.round(deg) % 360) + 360) % 360;
    return [PAL_R[i], PAL_G[i], PAL_B[i]];
  }

  // HA hue (0-360) → canvas angle, for placing the handle
  function hueToCanvas(haHue) {
    return HUE_TO_CANVAS[((Math.round(haHue) % 360) + 360) % 360];
  }

  // canvas angle → HA hue to send when user drags
  // Piecewise matching the wheel anchors:
  //   canvas 270 (12) = HA 240 BLUE
  //   canvas   0 ( 3) = HA 120 GREEN
  //   canvas  90 ( 6) = HA  60 YELLOW
  //   canvas 180 ( 9) = HA   0 RED
  // 9→12 arc goes through magenta/purple (HA 360→300→240)
  function canvasToHaHue(deg) {
    deg = ((deg % 360) + 360) % 360;
    if (deg < 90)        return 120 - (deg / 90) * 60;           // GREEN→YELLOW
    if (deg < 180)       return 60  - ((deg - 90) / 90) * 60;    // YELLOW→RED
    if (deg < 270) {                                               // RED→BLUE via purple
      const t = (deg - 180) / 90;
      return ((360 - t * 120) + 360) % 360;
    }
    return 240 - ((deg - 270) / 90) * 120;                       // BLUE→GREEN
  }

  class PalLightCard extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: "open" });
      this._hass = null; this._config = null;
      this._drag = false; this._ready = false; this._ctx = null;
    }

    setConfig(config) {
      if (!config.entity) throw new Error("pallight-card: entity required");
      this._config = config;
      this._build();
    }

    set hass(hass) {
      this._hass = hass;
      if (!this._ready) this._build();
      this._sync();
    }

    getCardSize() { return 5; }
    static getStubConfig() { return { entity: "light.pallight" }; }

    _build() {
      if (this._ready || !this._config) return;
      this._ready = true;
      this.shadowRoot.innerHTML = `<style>
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        :host{display:block}
        .card{
          background:var(--card-background-color,var(--ha-card-background,#1c1c1c));
          border-radius:var(--ha-card-border-radius,16px);
          box-shadow:var(--ha-card-box-shadow,0 2px 12px rgba(0,0,0,.4));
          padding:16px 14px 18px;
          display:flex;flex-direction:column;align-items:center;gap:10px;
          font-family:var(--primary-font-family,-apple-system,'Segoe UI',Roboto,Arial,sans-serif);
          color:var(--primary-text-color,#e0e0e0)
        }
        .name{font-size:12px;font-weight:700;letter-spacing:2.5px;
          color:var(--secondary-text-color,#aaa);text-transform:uppercase}
        .row-onoff{display:flex;width:100%;gap:10px;align-items:center}
        .spacer{flex:1}
        .btn{display:flex;align-items:center;justify-content:center;border:none;
          outline:none;cursor:pointer;font-family:inherit;font-weight:700;
          letter-spacing:1px;transition:filter .12s,transform .1s;
          -webkit-tap-highlight-color:transparent}
        .btn:active{filter:brightness(.75);transform:scale(.95)}
        .btn-on{width:82px;height:52px;border-radius:10px;font-size:15px;color:#fff;
          background:linear-gradient(150deg,#3ddc54,#1fa832);
          box-shadow:0 3px 10px rgba(0,0,0,.35)}
        .btn-off{width:82px;height:52px;border-radius:10px;font-size:15px;color:#fff;
          background:linear-gradient(150deg,#f0473a,#b52520);
          box-shadow:0 3px 10px rgba(0,0,0,.35)}
        .wheel-wrap{position:relative;width:280px;height:280px;
          cursor:crosshair;touch-action:none;flex-shrink:0}
        canvas{display:block}
        .handle{position:absolute;width:26px;height:26px;border-radius:50%;
          border:3px solid #fff;background:#555;
          box-shadow:0 2px 8px rgba(0,0,0,.7);
          transform:translate(-50%,-50%);pointer-events:none;
          transition:opacity .3s}
        .handle.effect-mode{opacity:.25}
        .row-ctrls{display:flex;width:100%;gap:8px}
        .ctrl{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
        .ctrl-label{font-size:9.5px;font-weight:700;letter-spacing:1.5px;
          color:var(--secondary-text-color,#777);text-transform:uppercase}
        .btn-up{width:100%;height:40px;border-radius:8px;color:#fff;font-size:12px;
          background:linear-gradient(150deg,#3ddc54,#1fa832);
          box-shadow:0 2px 6px rgba(0,0,0,.3)}
        .btn-dn{width:100%;height:40px;border-radius:8px;color:#fff;font-size:12px;
          background:linear-gradient(150deg,#f0473a,#b52520);
          box-shadow:0 2px 6px rgba(0,0,0,.3)}
        .btn-mode{width:100%;height:40px;border-radius:8px;color:#fff;font-size:12px;
          background:linear-gradient(150deg,#6b8cff,#3355cc);
          box-shadow:0 2px 6px rgba(0,0,0,.3)}
        .btn-mode.active{background:linear-gradient(150deg,#a259ff,#6620cc);
          box-shadow:0 2px 8px rgba(102,32,204,.5)}
        .status{font-size:10.5px;color:var(--secondary-text-color,#666);
          text-align:center;min-height:14px}
        .effect-name{font-size:10px;font-weight:700;letter-spacing:1.5px;
          color:var(--secondary-text-color,#888);text-transform:uppercase;
          text-align:center;min-height:13px;margin-top:-4px}
        .body-wrap{
          display:flex;flex-direction:column;align-items:center;gap:10px;
          width:100%;
          opacity:1;
          pointer-events:auto;
          transition:opacity .4s ease}
        .body-wrap.is-off{
          opacity:.35;
          pointer-events:none}
      </style>
      <div class="card">
        <div class="name" id="name">TOUCH-1</div>
        <div class="row-onoff">
          <button class="btn btn-on"  id="btn-on">ON</button>
          <div class="spacer"></div>
          <button class="btn btn-off" id="btn-off">OFF</button>
        </div>
        <div class="body-wrap" id="body-wrap">
          <div class="wheel-wrap" id="wrap">
            <canvas id="canvas" width="280" height="280"></canvas>
            <div class="handle" id="handle"></div>
          </div>
          <div class="effect-name" id="effect-name"></div>
          <div class="row-ctrls">
            <div class="ctrl">
              <button class="btn btn-up" id="bright-up">UP</button>
              <span class="ctrl-label">BRIGHT</span>
              <button class="btn btn-dn" id="bright-dn">DOWN</button>
            </div>
            <div class="ctrl">
              <button class="btn btn-up" id="speed-up">UP</button>
              <span class="ctrl-label">SPEED</span>
              <button class="btn btn-dn" id="speed-dn">DOWN</button>
            </div>
            <div class="ctrl">
              <button class="btn btn-mode" id="mode-up">NEXT</button>
              <span class="ctrl-label">MODE</span>
              <button class="btn btn-mode" id="mode-dn">PREV</button>
            </div>
          </div>
          <div class="status" id="status"></div>
        </div>
      </div>`;
      this._drawWheel();
      this._wire();
      this._moveHandle(120);
      // Set transition directly on element so it survives any CSS specificity battles
      const bw = this.shadowRoot.getElementById("body-wrap");
      if (bw) bw.style.transition = "opacity 0.4s ease";
    }

    _drawWheel() {
      const canvas = this.shadowRoot.getElementById("canvas");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      this._ctx = ctx;
      for (let deg = 0; deg < 360; deg++) {
        const [r,g,b] = degToRgb(deg);
        const a0 = ((deg - 0.7) * Math.PI) / 180;
        const a1 = ((deg + 0.7) * Math.PI) / 180;
        const gr = ctx.createRadialGradient(CX,CY,INNER_R,CX,CY,OUTER_R);
        const rb = Math.round(r*.55), gb = Math.round(g*.55), bb = Math.round(b*.55);
        const rl = Math.min(255,r+20), gl = Math.min(255,g+20), bl = Math.min(255,b+20);
        gr.addColorStop(0,    `rgba(${r},${g},${b},0)`);
        gr.addColorStop(0.06, `rgba(${rl},${gl},${bl},1)`);
        gr.addColorStop(0.88, `rgba(${r},${g},${b},1)`);
        gr.addColorStop(1,    `rgba(${rb},${gb},${bb},1)`);
        ctx.beginPath();
        ctx.moveTo(CX,CY);
        ctx.arc(CX,CY,OUTER_R,a0,a1+0.02);
        ctx.closePath();
        ctx.fillStyle = gr;
        ctx.fill();
      }
      ctx.save();
      ctx.globalCompositeOperation = "destination-out";
      ctx.beginPath();
      ctx.arc(CX,CY,INNER_R,0,Math.PI*2);
      ctx.fill();
      ctx.restore();
      ctx.beginPath();
      ctx.arc(CX,CY,INNER_R-1,0,Math.PI*2);
      ctx.fillStyle = "rgba(0,0,0,.88)";
      ctx.fill();
      this._dot(null);
    }

    _dot(col) {
      if (!this._ctx) return;
      this._ctx.beginPath();
      this._ctx.arc(CX,CY,22,0,Math.PI*2);
      this._ctx.fillStyle = col || "rgba(40,40,40,.95)";
      this._ctx.fill();
    }

    _moveHandle(haHue) {
      const cd  = hueToCanvas(haHue);
      const rad = cd * Math.PI / 180;
      const x   = CX + HANDLE_R * Math.cos(rad);
      const y   = CY + HANDLE_R * Math.sin(rad);
      const [r,g,b] = degToRgb(cd);
      const col = `rgb(${r},${g},${b})`;
      const h = this.shadowRoot.getElementById("handle");
      if (h) { h.style.left=`${x}px`; h.style.top=`${y}px`; h.style.background=col; }
      this._dot(col);
    }

    _clearHandle() {
      const h = this.shadowRoot.getElementById("handle");
      if (h) h.style.background = "rgba(80,80,80,.6)";
      this._dot(null);
    }

    _wire() {
      const $ = id => this.shadowRoot.getElementById(id);
      const on = (id, evt, fn) => { const el = $(id); if (el) el.addEventListener(evt, fn); };
      const wrap = $("wrap");
      if (wrap) {
        wrap.addEventListener("pointerdown",   e => this._pd(e));
        wrap.addEventListener("pointermove",   e => this._pm(e));
        wrap.addEventListener("pointerup",     e => this._pu(e));
        wrap.addEventListener("pointercancel", e => this._pu(e));
      }
      on("btn-on",   "click", () => this._power(true));
      on("btn-off",  "click", () => this._power(false));
      on("bright-up","click", () => this._bright(1));
      on("bright-dn","click", () => this._bright(-1));
      on("speed-up", "click", () => this._speed(1));
      on("speed-dn", "click", () => this._speed(-1));
      on("mode-up",  "click", () => this._cycleEffect(1));
      on("mode-dn",  "click", () => this._cycleEffect(-1));
    }

    _xy(e) {
      const r = this.shadowRoot.getElementById("wrap").getBoundingClientRect();
      return { x: e.clientX-r.left-CX, y: e.clientY-r.top-CY };
    }

    _pd(e) {
      const {x,y} = this._xy(e);
      if (Math.hypot(x,y) < INNER_R-8 || Math.hypot(x,y) > OUTER_R+8) return;
      e.preventDefault();
      this._drag = true;
      this._lastSent = 0;        // timestamp of last colour send
      e.currentTarget.setPointerCapture(e.pointerId);
      this._apply(x,y,true);    // send immediately on touch-down
    }
    _pm(e) {
      if (!this._drag) return;
      e.preventDefault();
      const {x,y} = this._xy(e);
      const now = Date.now();
      // Throttle to ~50ms intervals matching native app drag rate
      if (now - this._lastSent >= 50) {
        this._lastSent = now;
        this._apply(x,y,true);  // stream colour while dragging
      } else {
        this._apply(x,y,false); // update handle visually only
      }
    }
    _pu(e) {
      if (!this._drag) return;
      this._drag = false;
      const {x,y} = this._xy(e);
      this._apply(x,y,true);   // send final position on release
    }

    _apply(x, y, send) {
      const deg   = ((Math.atan2(y,x)*180/Math.PI)%360+360)%360;
      const haHue = canvasToHaHue(deg);
      const [r,g,b] = degToRgb(deg);
      const col   = `rgb(${r},${g},${b})`;
      const scale = HANDLE_R / (Math.hypot(x,y) || 1);
      const h = this.shadowRoot.getElementById("handle");
      if (h) { h.style.left=`${CX+x*scale}px`; h.style.top=`${CY+y*scale}px`; h.style.background=col; }
      this._dot(col);
      if (send && this._hass && this._config)
        this._hass.callService("light","turn_on",{entity_id:this._config.entity,hs_color:[haHue,100]})
          .catch(e => console.warn("pallight-card: colour failed", e));
    }

    _power(on) {
      if (!this._hass || !this._config) return;
      this._hass.callService("light", on ? "turn_on" : "turn_off", {entity_id: this._config.entity})
        .catch(e => console.warn("pallight-card: power failed", e));
    }

    _bright(dir) {
      if (!this._hass || !this._config) return;
      this._hass.callService("light", "turn_on", {
        entity_id: this._config.entity,
        brightness_step: dir * SPEED_STEP,
      }).catch(e => console.warn("pallight-card: brightness failed", e));
    }

    _speed(dir) {
      if (!this._hass || !this._config) return;
      const state = this._hass.states[this._config.entity];
      const effect = state && state.attributes.effect;
      if (!effect) return;
      this._hass.callService("light", "turn_on", {
        entity_id: this._config.entity,
        brightness_step: dir * SPEED_STEP,
      }).catch(e => console.warn("pallight-card: speed failed", e));
    }

    _cycleEffect(dir) {
      if (!this._hass || !this._config) return;
      const state = this._hass.states[this._config.entity];
      const current = state && state.attributes.effect;
      const currentIdx = current ? EFFECTS.indexOf(current) : -1;
      let nextIdx;
      if (currentIdx === -1) {
        nextIdx = dir > 0 ? 0 : EFFECTS.length - 1;
      } else {
        nextIdx = (currentIdx + dir + EFFECTS.length) % EFFECTS.length;
      }
      const effect = EFFECTS[nextIdx];
      this._hass.callService("light", "turn_on", {
        entity_id: this._config.entity,
        effect,
      }).catch(e => console.warn("pallight-card: effect failed", e));
    }

    _sync() {
      if (!this._hass || !this._config || !this._ready) return;
      const state = this._hass.states[this._config.entity];
      if (!state) return;

      const nameEl = this.shadowRoot.getElementById("name");
      if (nameEl) nameEl.textContent =
        (this._config.name || state.attributes.friendly_name || "TOUCH-1").toUpperCase();

      const isOn   = state.state === "on";
      const hs     = state.attributes.hs_color;
      const effect = state.attributes.effect;
      const handle = this.shadowRoot.getElementById("handle");
      const effectNameEl = this.shadowRoot.getElementById("effect-name");
      const modeUpBtn = this.shadowRoot.getElementById("mode-up");
      const modeDnBtn = this.shadowRoot.getElementById("mode-dn");

      // Fade + disable the entire body when off; ON/OFF buttons are outside it
      const bodyWrap = this.shadowRoot.getElementById("body-wrap");
      if (bodyWrap) {
        bodyWrap.style.opacity = isOn ? "1" : "0.35";
        bodyWrap.style.pointerEvents = isOn ? "auto" : "none";
      }

      if (isOn && effect) {
        // Effect mode — park handle at 12 o'clock, dim it, show effect name
        this._moveHandle(240);   // 240° HA hue = BLUE = 12 o'clock on the wheel
        if (handle) handle.classList.add("effect-mode");
        this._dot(null);         // clear centre dot colour
        if (effectNameEl) effectNameEl.textContent = effect.toUpperCase();
        if (modeUpBtn) modeUpBtn.classList.add("active");
        if (modeDnBtn) modeDnBtn.classList.add("active");
      } else if (isOn && hs) {
        // Colour mode
        this._moveHandle(hs[0]);
        if (handle) handle.classList.remove("effect-mode");
        if (effectNameEl) effectNameEl.textContent = "";
        if (modeUpBtn) modeUpBtn.classList.remove("active");
        if (modeDnBtn) modeDnBtn.classList.remove("active");
      } else {
        // Off or unknown
        this._clearHandle();
        if (handle) handle.classList.remove("effect-mode");
        if (effectNameEl) effectNameEl.textContent = "";
        if (modeUpBtn) modeUpBtn.classList.remove("active");
        if (modeDnBtn) modeDnBtn.classList.remove("active");
      }

      const st = this.shadowRoot.getElementById("status");
      if (st) {
        if (!isOn) { st.textContent = "Off"; return; }
        const bri = state.attributes.brightness;
        if (effect) {
          // In effect mode brightness maps to speed: 255=fastest, 0=slowest
          const speedPct = bri != null ? Math.round(bri / 255 * 100) : null;
          st.textContent = ["On", effect, speedPct != null ? `Speed ${speedPct}%` : null]
            .filter(Boolean).join(" · ");
        } else {
          const pct = bri != null ? `${Math.round(bri / 255 * 100)}%` : null;
          const hue = hs ? `Hue ${Math.round(hs[0])}°` : null;
          st.textContent = ["On", pct, hue].filter(Boolean).join(" · ");
        }
      }
    }
  }

  customElements.define("pallight-card", PalLightCard);
  window.customCards = window.customCards || [];
  const idx = window.customCards.findIndex(c => c.type==="pallight-card");
  if (idx > -1) window.customCards.splice(idx,1);
  window.customCards.push({
    type:"pallight-card",
    name:"Emulated PalLighting Color Wheel and control",
    description:`TOUCH-1 colour wheel + effects — v${VERSION}`,
    preview:false,
  });
  console.info(
    `%c PALLIGHT-CARD %c v${VERSION} `,
    "background:#1fa832;color:#fff;padding:2px 6px;border-radius:3px 0 0 3px;font-weight:700",
    "background:#222;color:#aaa;padding:2px 6px;border-radius:0 3px 3px 0"
  );
})();

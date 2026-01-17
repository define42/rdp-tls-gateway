package main

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevBoxGateway</title>
  <style>
    :root { --bg:#0a0f16; --bg-2:#0b151f; --panel:rgba(10,16,27,0.92); --panel-strong:#0d1524; --accent:#2dd4bf; --accent-2:#f59e0b; --accent-3:#fb7185; --muted:#9aa4b2; --line:rgba(255,255,255,0.08); --shadow:0 30px 80px rgba(2,6,23,0.55); }
    body { margin:0; font-family: "Space Grotesk", "Sora", "Avenir Next", sans-serif; background:
      radial-gradient(circle at 12% 10%, rgba(45,212,191,0.26), transparent 45%),
      radial-gradient(circle at 88% 6%, rgba(245,158,11,0.18), transparent 40%),
      radial-gradient(circle at 90% 88%, rgba(251,113,133,0.16), transparent 45%),
      linear-gradient(180deg, var(--bg), var(--bg-2));
      color:#e6edf7; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; position:relative; overflow:hidden; }
    body::before, body::after { content:""; position:fixed; inset:-20% -10%; z-index:0; pointer-events:none; }
    body::before { background:radial-gradient(circle at 20% 20%, rgba(45,212,191,0.25), transparent 45%); filter:blur(40px); animation:bgFloat 14s ease-in-out infinite; }
    body::after { background:radial-gradient(circle at 80% 30%, rgba(245,158,11,0.2), transparent 42%); filter:blur(60px); animation:bgFloat 18s ease-in-out infinite reverse; }
    .card { position:relative; z-index:1; background:
      linear-gradient(160deg, rgba(10,16,27,0.95), rgba(4,8,15,0.98)) padding-box,
      linear-gradient(120deg, rgba(45,212,191,0.5), rgba(245,158,11,0.4), rgba(251,113,133,0.35)) border-box;
      border:1px solid transparent; border-radius:20px; padding:36px 40px; max-width:520px; width:100%; box-shadow:var(--shadow); animation:cardEnter 700ms ease both; }
    h1 { margin:0 0 8px; font-size:32px; color:#eafaf7; letter-spacing:0.02em; }
    p { margin:8px 0; line-height:1.5; color:var(--muted); }
    form { display:grid; gap:14px; margin-top:18px; width:100%; justify-items:stretch; }
    .field { width:100%; }
    label { display:block; margin-bottom:6px; font-size:12px; color:var(--muted); letter-spacing:0.1em; text-transform:uppercase; }
    input { display:block; width:100%; box-sizing:border-box; background:rgba(7,12,21,0.9); border:1px solid var(--line); color:#e6edf7; border-radius:12px; padding:11px 12px; font-size:15px; transition:border-color 150ms ease, box-shadow 150ms ease; }
    input:focus { outline:none; border-color:rgba(45,212,191,0.7); box-shadow:0 0 0 3px rgba(45,212,191,0.18); }
    button { width:100%; box-sizing:border-box; border:0; border-radius:12px; padding:12px 14px; font-weight:700; letter-spacing:0.02em; background:linear-gradient(120deg, var(--accent), var(--accent-2)); color:#052025; cursor:pointer; box-shadow:0 12px 25px rgba(45,212,191,0.25); transition:transform 150ms ease, box-shadow 150ms ease, filter 150ms ease; }
    button:hover { transform:translateY(-1px); filter:brightness(1.05); box-shadow:0 16px 35px rgba(45,212,191,0.35); }
    .error { margin-top:12px; padding:10px 12px; border-radius:12px; border:1px solid rgba(251,113,133,0.5); background:rgba(251,113,133,0.12); color:#ffd2dc; font-size:13px; }
    @keyframes bgFloat { 0%, 100% { transform:translate3d(0, 0, 0); } 50% { transform:translate3d(12px, -16px, 0); } }
    @keyframes cardEnter { from { opacity:0; transform:translateY(18px) scale(0.98); } to { opacity:1; transform:translateY(0) scale(1); } }
    @media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
  </style>
</head>
<body>
  <div class="card">
    <h1>DevBoxGateway</h1>
    <p>Sign in to DevBoxGateway</p>
    {{ERROR}}
    <form method="post" action="/login">
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>
`

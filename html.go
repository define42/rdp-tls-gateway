package main

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevBoxGateway</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 15% 15%, rgba(56,189,248,0.18), transparent 40%),
      radial-gradient(circle at 85% 5%, rgba(14,165,233,0.12), transparent 35%),
      var(--bg);
      color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
    .card { background:linear-gradient(160deg, rgba(15,23,42,0.96), rgba(2,6,23,0.96)); border:1px solid var(--line); border-radius:18px; padding:36px 40px; max-width:520px; width:100%; box-shadow:0 24px 70px rgba(0,0,0,0.4); }
    h1 { margin:0 0 12px; font-size:30px; color:var(--accent); }
    p { margin:8px 0; line-height:1.5; color:var(--muted); }
    form { display:grid; gap:14px; margin-top:18px; width:100%; justify-items:stretch; }
    .field { width:100%; }
    label { display:block; margin-bottom:6px; font-size:13px; color:var(--muted); letter-spacing:0.3px; text-transform:uppercase; }
    input { display:block; width:100%; box-sizing:border-box; background:#0b1224; border:1px solid var(--line); color:#e2e8f0; border-radius:10px; padding:10px 12px; font-size:15px; }
    button { width:100%; box-sizing:border-box; border:0; border-radius:10px; padding:12px 14px; font-weight:600; background:var(--accent); color:#062238; cursor:pointer; }
    .error { margin-top:12px; padding:10px 12px; border-radius:10px; border:1px solid rgba(248,113,113,0.4); background:rgba(248,113,113,0.12); color:#fecaca; font-size:13px; }
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

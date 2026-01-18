package main

const loginHTML = `<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevBoxGateway</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
</head>
<body class="bg-body-tertiary d-flex align-items-center justify-content-center min-vh-100 py-4">
  <main class="container">
    <div class="row justify-content-center">
      <div class="col-12 col-md-7 col-lg-5 col-xl-4">
        <div class="card shadow-sm">
          <div class="card-body p-4">
            <h1 class="h4 mb-2">DevBoxGateway</h1>
            <p class="text-body-secondary mb-3">Sign in to DevBoxGateway</p>
            {{ERROR}}
            <form method="post" action="/login" class="mt-2">
              <div class="mb-3">
                <label class="form-label" for="username">Username</label>
                <input class="form-control" id="username" name="username" autocomplete="username" required>
              </div>
              <div class="mb-3">
                <label class="form-label" for="password">Password</label>
                <input class="form-control" id="password" name="password" type="password" autocomplete="current-password" required>
              </div>
              <button class="btn btn-outline-primary w-100" type="submit">Continue</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </main>
</body>
</html>
`

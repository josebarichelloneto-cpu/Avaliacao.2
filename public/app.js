const status = document.getElementById("status");
const loginLinks = document.getElementById("login-links");
const logoutForm = document.getElementById("logout-form");
 
fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    if (user) {
      status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
      loginLinks.hidden = true;
      logoutForm.hidden = false;
    } else {
      status.textContent = "Nenhuma sessão neste navegador.";
      loginLinks.hidden = false;
      logoutForm.hidden = true;
    }
  })
  .catch(() => {
    status.textContent = "Não foi possível consultar a sessão.";
  });

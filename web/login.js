const form = document.querySelector("#auth-form");
const submit = document.querySelector("#auth-submit");
const errorMessage = document.querySelector("#auth-error");

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

async function initializeLogin() {
  submit.disabled = true;
  try {
    const response = await fetch("/api/session", { cache: "no-store" });
    const session = await response.json();
    if (!response.ok) throw new Error(session.error || "Could not verify your session.");
    if (session.user) {
      window.location.replace("/");
      return;
    }

    submit.disabled = false;
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not initialize authentication.");
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  const password = document.querySelector("#auth-password").value;

  submit.disabled = true;
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#auth-username").value,
        password,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Could not sign in to the analyzer.");
    window.location.replace("/");
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not sign in to the analyzer.");
    submit.disabled = false;
  }
});

initializeLogin();

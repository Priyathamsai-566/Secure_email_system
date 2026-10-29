const API = "http://127.0.0.1:8000/api";
const $ = (selector) => document.querySelector(selector);

let currentUser = null;
let selectedMessageId = null;

function otherUser() {
  return currentUser === "alice" ? "bob" : "alice";
}

function displayName(userId) {
  return userId
    ? userId.charAt(0).toUpperCase() + userId.slice(1)
    : "";
}

async function api(path, options = {}) {
  let response;

  try {
    response = await fetch(`${API}${path}`, {
      ...options,
      credentials: "include",
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {}),
      },
    });
  } catch {
    throw new Error("Unable to connect to the server. Check that the backend is running.");
  }

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    throw new Error(
      data && data.detail
        ? data.detail
        : `Request failed (${response.status}).`
    );
  }

  return data;
}

function showNotice(message, type = "success") {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice ${
    type === "error" ? "error" : type === "warning" ? "warning" : ""
  }`;
  notice.hidden = false;

  window.setTimeout(() => {
    notice.hidden = true;
  }, 7000);
}

function showError(error) {
  showNotice(error.message || String(error), "error");
}

function showLogin() {
  currentUser = null;
  selectedMessageId = null;

  $("#app-shell").hidden = true;
  $("#login-screen").hidden = false;
  $("#login-password").value = "";
  $("#login-error").textContent = "";
  $("#login-error").hidden = true;
  $("#login-button").disabled = false;
  $("#login-button").textContent = "Log in";

  $("#login-username").focus();
}

async function showApplication(userId) {
  currentUser = userId;

  $("#login-screen").hidden = true;
  $("#app-shell").hidden = false;
  $("#signed-in-user").textContent = displayName(userId);
  $("#dashboard-user").textContent = displayName(userId);
  $("#compose-sender").value = displayName(userId);

  const recipientId = otherUser();
  const recipientName = displayName(recipientId);

  $("#compose-recipient").replaceChildren(
    new Option(recipientName, recipientId)
  );
  $("#contact-id").replaceChildren(
    new Option(recipientName, recipientId)
  );

  await refreshDashboard();
  await refreshKeyInfo();
}

async function checkExistingSession() {
  try {
    const session = await api("/auth/me");
    await showApplication(session.user_id);
  } catch {
    showLogin();
  }
}

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.remove("active");
  });

  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.remove("active");
  });

  const targetView = $(`#view-${name}`);
  const targetButton = document.querySelector(
    `.nav-button[data-view="${name}"]`
  );

  if (!targetView || !targetButton) return;

  targetView.classList.add("active");
  targetButton.classList.add("active");

  if (name === "dashboard") refreshDashboard().catch(showError);
  if (name === "inbox") loadInbox().catch(showError);
  if (name === "contacts") loadContacts().catch(showError);
  if (name === "keys") refreshKeyInfo().catch(showError);
}

async function refreshDashboard() {
  if (!currentUser) return;

  const fingerprint = await api(
    `/keys/${encodeURIComponent(currentUser)}/fingerprint`
  ).catch(() => null);

  $("#dashboard-fingerprint").textContent = fingerprint
    ? fingerprint.fingerprint
    : "Key pair not generated";

  const messages = await api(
    `/inbox/${encodeURIComponent(currentUser)}`
  );

  $("#dashboard-inbox-count").textContent = String(messages.length);
}

async function refreshKeyInfo() {
  if (!currentUser) return;

  try {
    const result = await api(
      `/keys/${encodeURIComponent(currentUser)}/fingerprint`
    );

    $("#key-fingerprint").textContent = result.fingerprint;
    $("#export-key").href =
      `${API}/keys/${encodeURIComponent(currentUser)}/public`;
  } catch {
    $("#key-fingerprint").textContent = "Key pair not generated";
    $("#export-key").href = "#";
  }
}

async function loadInbox() {
  if (!currentUser) return;

  const messages = await api(
    `/inbox/${encodeURIComponent(currentUser)}`
  );
  const list = $("#inbox-list");

  list.replaceChildren();

  if (messages.length === 0) {
    const empty = document.createElement("div");
    empty.className = "card";
    empty.textContent = "Your inbox is empty.";
    list.append(empty);
    return;
  }

  messages.forEach((message) => {
    const item = document.createElement("article");
    item.className = "list-item";

    const details = document.createElement("div");

    const title = document.createElement("strong");
    title.textContent = `From ${message.sender_id}`;

    const meta = document.createElement("p");
    meta.className = "muted";
    meta.textContent = `${message.created_at} · encrypted package`;

    details.append(title, meta);

    const openButton = document.createElement("button");
    openButton.className = "button secondary";
    openButton.type = "button";
    openButton.textContent = "Open";
    openButton.addEventListener("click", () => {
      openMessage(message.message_id).catch(showError);
    });

    item.append(details, openButton);
    list.append(item);
  });
}

async function openMessage(messageId) {
  const packageData = await api(
    `/messages/${encodeURIComponent(messageId)}`
  );

  selectedMessageId = messageId;

  $("#message-panel").hidden = false;
  $("#message-title").textContent =
    `Message from ${packageData.sender_id}`;
  $("#message-meta").textContent =
    `ID: ${packageData.message_id} · Created: ${packageData.created_at}`;
  $("#signature-status").textContent = "Not checked";
  $("#trust-status").textContent = "Unknown";
  $("#decryption-status").textContent = "Not attempted";
  $("#plaintext-panel").hidden = true;
  $("#tamper-message-id").value = messageId;

  $("#message-panel").scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

/* Login */

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const errorBox = $("#login-error");
  const button = $("#login-button");

  errorBox.textContent = "";
  errorBox.hidden = true;
  button.disabled = true;
  button.textContent = "Signing in…";

  try {
    const result = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value.trim().toLowerCase(),
        password: $("#login-password").value,
      }),
    });

    $("#login-password").value = "";
    await showApplication(result.user_id);
  } catch (error) {
    if (error.message === "Incorrect username or password.") {
      errorBox.textContent =
        "Invalid username or password. Please try again.";
    } else {
      errorBox.textContent =
        error.message || "Sign-in failed. Please try again.";
    }

    errorBox.hidden = false;
    $("#login-password").value = "";
    $("#login-password").focus();
  } finally {
    button.disabled = false;
    button.textContent = "Log in";
  }
});

/* Logout */

$("#logout-button").addEventListener("click", async () => {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch (error) {
    showError(error);
  } finally {
    showLogin();
  }
});

/* Message details, signature verification, and decryption */

$("#close-message").addEventListener("click", () => {
  $("#message-panel").hidden = true;
  selectedMessageId = null;
});

$("#verify-message").addEventListener("click", async () => {
  if (!selectedMessageId || !currentUser) return;

  try {
    const result = await api(
      `/messages/${encodeURIComponent(selectedMessageId)}/verify`,
      {
        method: "POST",
        body: JSON.stringify({ recipient_id: currentUser }),
      }
    );

    $("#signature-status").textContent =
      result.signature_valid ? "Valid" : "Invalid";
    $("#trust-status").textContent = result.sender_trust;

    showNotice(
      result.signature_valid
        ? `Signature valid. Sender trust is ${result.sender_trust}.`
        : "Signature invalid. Do not treat this message as authentic.",
      result.signature_valid ? "success" : "warning"
    );
  } catch (error) {
    showError(error);
  }
});

$("#decrypt-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!selectedMessageId || !currentUser) return;

  try {
    const result = await api(
      `/messages/${encodeURIComponent(selectedMessageId)}/decrypt`,
      {
        method: "POST",
        body: JSON.stringify({
          user_id: currentUser,
          password: $("#decrypt-password").value,
        }),
      }
    );

    $("#decryption-status").textContent =
      "Successful; GCM authentication passed";
    $("#plaintext-subject").textContent = result.subject;
    $("#plaintext-body").textContent = result.body;
    $("#plaintext-panel").hidden = false;
  } catch (error) {
    $("#decryption-status").textContent =
      "Failed; plaintext not accepted";
    $("#plaintext-panel").hidden = true;
    showError(error);
  } finally {
    $("#decrypt-password").value = "";
  }
});

/* Compose and send */

$("#compose-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) return;

  try {
    const result = await api("/messages/send", {
      method: "POST",
      body: JSON.stringify({
        sender_id: currentUser,
        recipient_id: $("#compose-recipient").value,
        password: $("#compose-password").value,
        subject: $("#compose-subject").value,
        body: $("#compose-body").value,
      }),
    });

    $("#compose-password").value = "";
    $("#compose-subject").value = "";
    $("#compose-body").value = "";
    $("#tamper-message-id").value = result.message_id;

    showNotice(`Encrypted and signed. Message ID: ${result.message_id}`);
  } catch (error) {
    showError(error);
  }
});

/* Key management */

$("#key-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) return;

  try {
    const result = await api("/keys/generate", {
      method: "POST",
      body: JSON.stringify({
        user_id: currentUser,
        password: $("#key-password").value,
      }),
    });

    $("#key-password").value = "";
    $("#key-fingerprint").textContent = result.fingerprint;
    $("#dashboard-fingerprint").textContent = result.fingerprint;
    $("#export-key").href =
      `${API}/keys/${encodeURIComponent(currentUser)}/public`;

    showNotice(`Key pair generated. Fingerprint: ${result.fingerprint}`);
  } catch (error) {
    showError(error);
  }
});

/* Contacts and trust */

$("#contact-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) return;

  try {
    const result = await api("/contacts/import", {
      method: "POST",
      body: JSON.stringify({
        owner_id: currentUser,
        contact_id: $("#contact-id").value,
        display_name: $("#contact-name").value,
        public_key_pem: $("#contact-pem").value,
        accept_replacement: $("#accept-replacement").checked,
      }),
    });

    showNotice(`Imported ${result.contact_id}; trust remains ${result.trust}.`);
    $("#contact-pem").value = "";
    $("#accept-replacement").checked = false;

    await loadContacts();
  } catch (error) {
    showError(error);
  }
});

async function loadContacts() {
  if (!currentUser) return;

  const contacts = await api(
    `/contacts/${encodeURIComponent(currentUser)}`
  );
  const list = $("#contacts-list");

  list.replaceChildren();

  if (contacts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No contacts have been imported.";
    list.append(empty);
    return;
  }

  contacts.forEach((contact) => {
    const item = document.createElement("article");
    item.className = "list-item";

    const text = document.createElement("div");

    const title = document.createElement("strong");
    title.textContent =
      `${contact.display_name} (${contact.contact_id})`;

    const fingerprint = document.createElement("p");
    fingerprint.className = "fingerprint";
    fingerprint.textContent = contact.fingerprint;

    const trust = document.createElement("p");
    trust.className = "muted";
    trust.textContent = `Trust: ${contact.trust}`;

    text.append(title, fingerprint, trust);

    const controls = document.createElement("div");
    controls.className = "row";

    const trustSelect = document.createElement("select");

    ["unknown", "trusted", "untrusted"].forEach((value) => {
      const option = new Option(value, value);
      option.selected = value === contact.trust;
      trustSelect.add(option);
    });

    const saveButton = document.createElement("button");
    saveButton.className = "button secondary";
    saveButton.type = "button";
    saveButton.textContent = "Save trust";

    saveButton.addEventListener("click", async () => {
      try {
        await api("/trust", {
          method: "POST",
          body: JSON.stringify({
            owner_id: currentUser,
            contact_id: contact.contact_id,
            status: trustSelect.value,
            method: "Manual local decision",
            notes: "",
          }),
        });

        showNotice(`Trust updated to ${trustSelect.value}.`);
        await loadContacts();
      } catch (error) {
        showError(error);
      }
    });

    controls.append(trustSelect, saveButton);
    item.append(text, controls);
    list.append(item);
  });
}

/* Local certificate authority */

$("#ca-init-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const result = await api("/ca/initialize", {
      method: "POST",
      body: JSON.stringify({
        password: $("#ca-password").value,
      }),
    });

    $("#ca-password").value = "";
    showNotice(
      `Certificate authority initialized. Fingerprint: ${result.ca_fingerprint}`
    );
  } catch (error) {
    showError(error);
  }
});

$("#ca-issue-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) return;

  try {
    const result = await api("/ca/issue", {
      method: "POST",
      body: JSON.stringify({
        subject_id: currentUser,
        ca_password: $("#ca-issue-password").value,
      }),
    });

    $("#ca-issue-password").value = "";
    $("#certificate-pem").value = result.certificate_pem;
    showNotice(`Certificate issued for ${result.subject_id}.`);
  } catch (error) {
    showError(error);
  }
});

$("#validate-certificate").addEventListener("click", async () => {
  if (!currentUser) return;

  try {
    const result = await api("/ca/validate", {
      method: "POST",
      body: JSON.stringify({
        subject_id: currentUser,
        certificate_pem: $("#certificate-pem").value,
      }),
    });

    $("#certificate-result").textContent =
      JSON.stringify(result, null, 2);
  } catch (error) {
    showError(error);
  }
});

/* Security lab */

$("#tamper-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) return;

  try {
    const messageId = encodeURIComponent(
      $("#tamper-message-id").value.trim()
    );

    const result = await api(`/lab/tamper/${messageId}`, {
      method: "POST",
      body: JSON.stringify({
        recipient_id: currentUser,
        field: $("#tamper-field").value,
      }),
    });

    $("#tamper-result").textContent =
      JSON.stringify(result, null, 2);

    showNotice(
      result.tampering_detected
        ? "Tampering detected by signature verification."
        : "Tamper test did not detect a change.",
      result.tampering_detected ? "success" : "warning"
    );
  } catch (error) {
    showError(error);
  }
});

/* Navigation and refresh buttons */

document.querySelectorAll(".nav-button").forEach((button) => {
  button.addEventListener("click", () => {
    showView(button.dataset.view);
  });
});

$("#refresh-dashboard").addEventListener("click", () => {
  refreshDashboard().catch(showError);
});

$("#refresh-inbox").addEventListener("click", () => {
  loadInbox().catch(showError);
});

/* Restore the session or show the login page. */
checkExistingSession();
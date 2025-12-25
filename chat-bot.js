/* =========================================
   CHATBOT WIDGET (AUTO-INJECT VERSION)
   ========================================= */
(function () {

  /* ---------- Inject CSS ---------- */
  const style = document.createElement("style");
  style.innerHTML = `
    #chat-btn {
      position: fixed;
      bottom: 80px;
      right: 20px;
      width: 55px;
      height: 55px;
      border-radius: 50%;
      background: rgb(136, 28, 28);
      color: #fff;
      display: flex;
      justify-content: center;
      align-items: center;
      cursor: pointer;
      border: none;
      font-size: 26px;
      z-index: 999999;
    }

    #chat-panel {
      position: fixed;
      bottom: -600px;
      right: 20px;
      width: 500px;
      height: 600px;
      background: #fff;
      box-shadow: 0 -2px 12px rgba(0,0,0,0.25);
      border-radius: 12px 12px 0 0;
      display: flex;
      flex-direction: column;
      transition: bottom 0.35s ease;
      z-index: 999998;
    }

    #chat-header {
      padding: 15px;
      background: rgb(136, 28, 28);
      color: #fff;
      font-weight: bold;
      border-radius: 12px 12px 0 0;
    }

    #chat-body {
      flex: 1;
      padding: 15px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
      font-size: 14px;
    }

    .msg {
      padding: 10px;
      border-radius: 8px;
      max-width: 90%;
    }
    .user-msg { background: #e0f0ff; align-self: flex-end; }
    .bot-msg { background: #f1f1f1; align-self: flex-start; }

    #loading {
      font-size: 12px;
      color: #777;
      display: none;
      padding-left: 15px;
    }

    #chat-input {
      display: flex;
      padding: 10px;
      border-top: 1px solid #ccc;
    }

    #msgBox {
      flex: 1;
      padding: 8px;
      border: 1px solid #ccc;
      border-radius: 5px;
    }

    #sendBtn {
      margin-left: 8px;
      padding: 8px 15px;
      border: none;
      background: rgb(136, 28, 28);
      color: #fff;
      cursor: pointer;
      border-radius: 5px;
    }

    @media (max-width: 480px) {
      #chat-panel {
        width: 100%;
        right: 0;
        height: 60vh;
      }
      #chat-btn {
        bottom: 80px;
        right: 15px;
      }

      #sendBtn {
        padding: 8px 10px;
        width: 60px;
        height: 36px;
    }
    }
  `;
  document.head.appendChild(style);

  /* ---------- Inject HTML ---------- */
  const wrapper = document.createElement("div");
  wrapper.innerHTML = `
    <button id="chat-btn">💬</button>

    <div id="chat-panel">
      <div id="chat-header">Chatbot</div>
      <div id="chat-body">
      <div class='msg bot-msg'>Hi! I’m an AI assistant for MES CMS. Ask me any questions related to MES CMS.</div>
      </div>
      <div id="loading">Waiting for reply...</div>

      <div id="chat-input">
        <input type="text" id="msgBox" placeholder="Type a message..." />
        <button id="sendBtn">Send</button>
      </div>
    </div>
  `;
  document.body.appendChild(wrapper);

  /* ---------- JS Logic ---------- */
  const btn = document.getElementById("chat-btn");
  const panel = document.getElementById("chat-panel");
  const body = document.getElementById("chat-body");
  const msgBox = document.getElementById("msgBox");
  const sendBtn = document.getElementById("sendBtn");
  const loading = document.getElementById("loading");

  let open = false;

  function openChat() {
    open = true;
    panel.style.bottom = "0";
  }

  function closeChat() {
    open = false;
    panel.style.bottom = "-600px";
  }

  // Button toggles chat
  btn.onclick = (e) => {
    e.stopPropagation();
    open ? closeChat() : openChat();
  };

  // Clicking outside closes chat
  document.addEventListener("click", (e) => {
    if (!open) return;

    const clickedInsidePanel = panel.contains(e.target);
    const clickedButton = btn.contains(e.target);

    if (!clickedInsidePanel && !clickedButton) {
      closeChat();
    }
  });

  // Sending chatbot messages
  async function sendMessage() {
    const text = msgBox.value.trim();
    if (!text) return;

    body.innerHTML += `<div class='msg user-msg'>${text}</div>`;
    loading.style.display = "block";
    msgBox.value = "";

    try {
      const authToken = localStorage.getItem("authToken");
      const res = await fetch("http://127.0.0.1:3001/chat", {
        method: "POST",
        headers: { 'Authorization': `Bearer ${authToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });

      const data = await res.json();
      loading.style.display = "none";

      body.innerHTML += `<div class='msg bot-msg'>${data.reply || "No reply"}</div>`;
      body.scrollTop = body.scrollHeight;

    } catch {
      loading.style.display = "none";
      body.innerHTML += `<div class='msg bot-msg'>Error: Could not get response.</div>`;
    }
  }

  sendBtn.onclick = sendMessage;
  msgBox.addEventListener("keypress", e => {
    if (e.key === "Enter") sendMessage();
  });

})();

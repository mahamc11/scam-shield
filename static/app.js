(function () {
  const micBtn = document.getElementById("micBtn");
  const descriptionBox = document.getElementById("descriptionBox");
  const voiceText = document.getElementById("voiceText");

  if (micBtn && (window.SpeechRecognition || window.webkitSpeechRecognition)) {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = navigator.language || "en-US";

    micBtn.addEventListener("click", () => {
      micBtn.textContent = "🎙️";
      recognition.start();
    });

    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      voiceText.value = transcript;
      descriptionBox.value = descriptionBox.value
        ? `${descriptionBox.value}\n${transcript}`
        : transcript;
      micBtn.textContent = "🎤";
    };

    recognition.onerror = () => {
      micBtn.textContent = "🎤";
    };
  }

  const chatWindow = document.getElementById("chatWindow");
  const chatInput = document.getElementById("chatInput");
  const sendChat = document.getElementById("sendChat");

  async function sendMessage() {
    if (!chatInput || !chatWindow) return;
    const msg = chatInput.value.trim();
    if (!msg) return;

    const userEl = document.createElement("div");
    userEl.className = "user-msg";
    userEl.textContent = msg;
    chatWindow.appendChild(userEl);
    chatInput.value = "";

    const res = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg }),
    });

    const data = await res.json();
    const botEl = document.createElement("div");
    botEl.className = "bot-msg";
    botEl.textContent = data.reply || "Please try again.";
    chatWindow.appendChild(botEl);
    chatWindow.scrollTop = chatWindow.scrollHeight;
  }

  if (sendChat) sendChat.addEventListener("click", sendMessage);
  if (chatInput) {
    chatInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") sendMessage();
    });
  }

  if (window.detectionData && window.Chart) {
    const { score, factors, phoneStatus, companyStatus } = window.detectionData;
    const baseOptions = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#edf2ff" } },
      },
    };

    const probabilityCtx = document.getElementById("probabilityChart");
    if (probabilityCtx) {
      new Chart(probabilityCtx, {
        type: "doughnut",
        data: {
          labels: ["Scam Probability", "Remaining Confidence"],
          datasets: [{
            data: [score, 100 - score],
            backgroundColor: ["#ff6b6b", "#63e6be"],
            borderWidth: 1,
          }],
        },
        options: baseOptions,
      });
    }

    const riskCtx = document.getElementById("riskChart");
    if (riskCtx) {
      new Chart(riskCtx, {
        type: "bar",
        data: {
          labels: Object.keys(factors),
          datasets: [{
            label: "Risk Factors",
            data: Object.values(factors),
            backgroundColor: "#5b8cff",
            borderRadius: 6,
          }],
        },
        options: {
          ...baseOptions,
          scales: {
            x: { ticks: { color: "#dce5ff", maxRotation: 20, minRotation: 0 } },
            y: { beginAtZero: true, max: 70, ticks: { color: "#dce5ff" } },
          },
        },
      });
    }

    const verifyCtx = document.getElementById("verificationChart");
    if (verifyCtx) {
      new Chart(verifyCtx, {
        type: "radar",
        data: {
          labels: ["Phone Verification", "Company Verification"],
          datasets: [{
            label: "Verification Status",
            data: [phoneStatus === "Verified" ? 90 : 35, companyStatus === "Verified" ? 90 : 40],
            backgroundColor: "rgba(99, 230, 190, 0.3)",
            borderColor: "#63e6be",
            borderWidth: 2,
          }],
        },
        options: {
          ...baseOptions,
          scales: { r: { suggestedMin: 0, suggestedMax: 100, angleLines: { color: "#345" }, grid: { color: "#345" }, pointLabels: { color: "#dce5ff" }, ticks: { color: "#dce5ff", backdropColor: "transparent" } } },
        },
      });
    }
  }
})();

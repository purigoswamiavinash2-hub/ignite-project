const API_URL = "http://127.0.0.1:8000/api/analyze-url";

document.getElementById("scanBtn").addEventListener("click", async () => {
  const url = document.getElementById("urlInput").value.trim();
  const resDiv = document.getElementById("result");

  if (!url) return;

  resDiv.style.display = "block";
  resDiv.innerHTML = "Checking link safety...";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();
    const color = data.risk_score >= 50 ? "#ef4444" : "#10b981";

    resDiv.innerHTML = `
      <div style="font-weight:700; color:${color}; margin-bottom:0.35rem">Risk Level: ${data.risk_level} (${data.risk_score}/100)</div>
      <div style="color:#94a3b8; font-size:0.8rem">${data.recommendation}</div>
    `;
  } catch (err) {
    resDiv.innerHTML = "<span style='color:#ef4444'>Cannot connect to ThreatGuard API server.</span>";
  }
});

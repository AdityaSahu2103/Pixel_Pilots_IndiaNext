// popup.js - Handles the popup UI interaction

document.getElementById('scanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('scanBtn');
    const loader = document.getElementById('loader');
    const resultDiv = document.getElementById('result');

    btn.style.display = 'none';
    loader.style.display = 'block';
    resultDiv.style.display = 'none';

    try {
        // 1. Get active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        // 2. Inject content script if not already there
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js']
            });
        } catch (e) {
            // Content script may already be injected, that's fine
        }

        // 3. Ask content script for page data
        chrome.tabs.sendMessage(tab.id, { action: "extract_content" }, async (response) => {
            if (!response) {
                showError("Could not read page content. Refresh the page and try again.");
                return;
            }

            // 4. Send to our local FastAPI backend
            try {
                const apiResponse = await fetch('http://127.0.0.1:8000/api/analyze/text', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        text: response.text + "\n\nURLs found: " + response.links.join(", "),
                        context: `Webpage: ${response.title} (${response.url})`
                    })
                });

                if (!apiResponse.ok) {
                    throw new Error(`Server returned ${apiResponse.status}`);
                }

                const data = await apiResponse.json();
                showResults(data);

            } catch (err) {
                showError("Is CyberShield AI Backend running? Failed to connect to http://127.0.0.1:8000. Start it via: uvicorn backend.main:app");
            }
        });

    } catch (err) {
        showError("Extension error: " + err.message);
    }
});

function showResults(data) {
    const loader = document.getElementById('loader');
    const resultDiv = document.getElementById('result');
    const severityText = document.getElementById('severityText');
    const riskScore = document.getElementById('riskScore');
    const threatList = document.getElementById('threatList');
    const summary = document.getElementById('summary');
    const btn = document.getElementById('scanBtn');

    loader.style.display = 'none';
    resultDiv.style.display = 'block';
    btn.style.display = 'block';
    btn.innerText = 'Scan Again';

    // Set Severity colors
    resultDiv.className = '';
    const sev = data.risk_score.severity.toLowerCase();

    if (sev === 'critical' || sev === 'high') {
        resultDiv.classList.add('danger');
        severityText.innerHTML = `<span class="text-red">⚠️ High Risk Detected</span>`;
    } else if (sev === 'medium') {
        resultDiv.classList.add('warning');
        severityText.innerHTML = `<span class="text-yellow">⚠ Medium Risk</span>`;
    } else {
        resultDiv.classList.add('safe');
        severityText.innerHTML = `<span class="text-green">✅ Safe Content</span>`;
    }

    riskScore.innerText = `${data.risk_score.overall_score.toFixed(1)} / 100`;

    // Threats Found
    threatList.innerHTML = '';
    let foundDetections = data.detections.filter(d => d.detected);

    if (foundDetections.length > 0) {
        foundDetections.forEach(d => {
            let t = document.createElement('span');
            t.className = 'threat-tag';
            t.innerText = d.threat_type;
            threatList.appendChild(t);
        });
    } else {
        threatList.innerHTML = '<span style="color:#94a3b8; font-size:12px;">No specific threats identified.</span>';
    }

    // LLM Summary
    if (data.explanation && data.explanation.summary) {
        summary.innerText = data.explanation.summary;
    }
}

function showError(msg) {
    const loader = document.getElementById('loader');
    const resultDiv = document.getElementById('result');
    const btn = document.getElementById('scanBtn');

    loader.style.display = 'none';
    resultDiv.style.display = 'block';
    resultDiv.className = 'danger';
    resultDiv.innerHTML = `<p style="color:#ef4444">${msg}</p>`;
    btn.style.display = 'block';
    btn.innerText = 'Retry';
}

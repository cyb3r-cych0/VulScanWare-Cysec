/// Globals
let socket;
let typeChart;
let  severityChart;
let threatGauge;
let timelineChart;
let riskDial;
let densityChart;
let attackTimeline = [];
let attackLabels = [];
let densityData = [];
let densityLabels = [];
let lastVulnCount = 0;
let scanStartTime = null;
let scanCompleted = false;
let scanActive = false;
const selectedVulns = new Set();
const generatingVulns = new Set();
let collapsedCards = new Set();
let scanState = "idle"; // idle | running | paused


//// Start Vulnerability Scanning
function startScan(){
    const target = document.getElementById("target").value;
    const urlLimit = document.getElementById("urlLimit").value;
    const depthLimit = document.getElementById("depthLimit").value;

    fetch(`/start?target=${encodeURIComponent(target)}&url_limit=${urlLimit}&depth_limit=${depthLimit}`,
      {method:"POST"}
    );
    // Reset timeline
    scanActive = false;
    scanStartTime = null;
    attackTimeline = [];
    attackLabels = [];

    if (timelineChart){
        timelineChart.data.labels = [];
        timelineChart.data.datasets[0].data = [];
        timelineChart.update();
    }

    densityData = [];
    densityLabels = [];
    lastVulnCount = 0;

    if (densityChart){
        densityChart.data.labels = [];
        densityChart.data.datasets[0].data = [];
        densityChart.update();
    }
    // Reset rendered feed cache
    window.renderedVulns = new Set();
    // Reconnect WebSocket
    if (socket) socket.close();
    connectSocket();
}

/// Reset UI
function fullResetUI(){
    scanStartTime = null;
    attackTimeline = [];
    attackLabels = [];
    densityData = [];
    densityLabels = [];
    lastVulnCount = 0;

    timelineChart.data.labels = [];
    timelineChart.data.datasets[0].data = [];
    timelineChart.update();

    densityChart.data.labels = [];
    densityChart.data.datasets[0].data = [];
    densityChart.update();

    document.getElementById("vulnFeed").innerHTML = "";
    document.getElementById("heatmap").innerHTML = "";

    window.renderedVulns = new Set();
}

/// Start Scan
function handleScan(){
    if (scanState === "idle"){
        startScan();
        scanState = "running";
        updateButtons();
    }
    else if (scanState === "paused"){
        fetch("/resume",{method:"POST"});
        scanState = "running";
        updateButtons();
    }
}

/// Stop Scan
function handleStop(){
    // If running → pause
    if (scanState === "running"){
        fetch("/stop",{method:"POST"});
        scanState = "paused";
        updateButtons(false);
    }
    // If paused OR completed → reset
    else if (scanState === "paused" || scanCompleted){
        fetch("/reset",{method:"POST"})
        .then(()=>{
            fullResetUI();
            scanState = "idle";
            scanCompleted = false;
            updateButtons(false);
        });
    }
}

/// Update UI Buttons Dynamically
function updateButtons(completed = false){
    const scanBtn = document.getElementById("scanBtn");
    const stopBtn = document.getElementById("stopBtn");

    if (scanState === "running"){
        scanBtn.textContent = "Running...";
        scanBtn.disabled = true;
        stopBtn.textContent = "Stop";
    }
    else if (scanState === "paused"){
        scanBtn.textContent = "Resume";
        scanBtn.disabled = false;
        stopBtn.textContent = "Reset";
    }
    else { // idle
        scanBtn.textContent = "Scan";
        scanBtn.disabled = false;
        stopBtn.textContent = completed ? "Reset" : "Stop"; // If scan just completed → allow reset
    }
}

/// ------------------- Initialize Charts ---------------------
function initCharts(){

    // XSS Type Distribution | Reflected | Stored | DOM
    typeChart = new Chart(document.getElementById("typeChart"),{
        type:"bar",
        data:{labels:[],datasets:[{label: "XSS Type",data:[],backgroundColor:"#38bdf8"}]},
        options:{
            responsive:true,
            scales:{
                y:{title:{display:true,text:"Total Links"}}
            }
        }
    });

    // XSS Vuln Severity
    severityChart = new Chart(document.getElementById("severityChart"),{
        type:"bar",
        data:{
            labels:["Critical","High","Medium","Low"],
            datasets:[{
                label:"Severity Distribution",
                data:[0,0,0,0],
                backgroundColor:["#dc2626","#ef4444","#facc15","#22c55e"]
            }]
        },
        options:{
            responsive:true,
            scales:{
                y:{title:{display:true,text:"Total Links"}}
            }
        }
    });

    // Threat Gauge | Threat Index | Menace
    threatGauge = new Chart(document.getElementById("threatGauge"),{
        type:"doughnut",
        data:{
            labels:["Risk","Safe"],
            datasets:[{
                data:[0,100],
                backgroundColor:["#ef4444","#1e293b"],
                borderWidth:0
            }]
        },
        options:{
            responsive:true,
            cutout:"75%",
            plugins:{
                legend:{display:false},
                tooltip:{enabled:false}
            },
            animation:{
                animateRotate:true,
                duration:800
            }
        }
    });

    // Vulnerabilities Over Time | Timeline
    timelineChart = new Chart(document.getElementById("timelineChart"),{
        type:"line",
        data:{
            labels:attackLabels,
            datasets:[{
                label:"Vulnerabilities Over Time",
                data:attackTimeline,
                borderColor:"#ef4444",
                backgroundColor:"rgba(239,68,68,0.2)",
                tension:0.3,
                fill:true
            }]
        },
        options:{
            responsive:true,
            animation:false,
            scales:{
                x:{title:{display:true,text:"Seconds"}},
                y:{title:{display:true,text:"Total Vulnerabilities"}}
            }
        }
    });

    // Vulnerabilities / Second - Density
    densityChart = new Chart(document.getElementById("densityChart"),{
        type:"line",
        data:{
            labels:densityLabels,
            datasets:[{
                label:"Vulnerabilities per Second",
                data:densityData,
                borderColor:"#38bdf8",
                backgroundColor:"rgba(56,189,248,0.2)",
                tension:0.3,
                fill:true
            }]
        },
        options:{
            responsive:true,
            animation:false,
            scales:{
                x:{title:{display:true,text:"Seconds"}},
                y:{title:{display:true,text:"Vulns / Sec"}}
            }
        }
    });

    // Risk Dial | Risk Level
    riskDial = new Chart(document.getElementById("riskDial"),{
        type:"doughnut",
        data:{
            labels:["Risk","Remaining"],
            datasets:[{
                data:[0,100],
                backgroundColor:["#22c55e","#1e293b"],
                borderWidth:0
            }]
        },
        options:{
            responsive:true,
            cutout:"70%",
            plugins:{
                legend:{display:false},
                tooltip:{enabled:false}
            },
            animation:{
                animateRotate:true,
                duration:1000
            }
        }
    });
}
initCharts();

//// --------------- Configure Web Socket ------------------
function connectSocket(){
    socket = new WebSocket("ws://" + location.host + "/ws");

    socket.onmessage = function(event){
        const data = JSON.parse(event.data);
        const analytics = data.analytics || {};
        const typeDist = analytics.type_distribution || {};
        const sevDist = analytics.severity_distribution || {};
        const threatIndex = analytics.threat_index || 0;
        const aiBtn = document.getElementById("aiBtn");

        aiBtn.disabled = data.phase !== "done";
        window.currentVulns = data.vulns;


        /// Header Phase Transition
        const header = document.getElementById("phaseHeader");
        const indicator = document.getElementById("phaseIndicator");

        header.className = "";

        if (data.phase === "crawling") {
            header.classList.add("phase-crawling");
            indicator.textContent = "● Crawling";
        }
        else if (data.phase === "scanning") {
            header.classList.add("phase-scanning");
            indicator.textContent = "● Scanning";
        }
        else if (data.phase === "stored-analysis") {
            header.classList.add("phase-stored-analysis");
            indicator.textContent = "● Stored XSS Analysis";
        }
        else if (data.phase === "dom-analysis") {
            header.classList.add("phase-dom-analysis");
            indicator.textContent = "● DOM XSS Analysis";
        }
        else if (data.phase === "done") {
            header.classList.add("phase-done");
            indicator.textContent = "● Complete";
        }
        // else if (data.phase === "ai") {
        //     header.classList.add("phase-ai");
        //     indicator.textContent = "● AI Analysis";
        // }
        else {
          indicator.textContent = "● Progress";
        }

        ///  Progress Bar Phase Transition
        const progressBar = document.getElementById("progressBar");

        if (data.phase === "crawling") {
            progressBar.style.background = "#38bdf8";
            progressBar.style.width = Math.min(data.urls.length * 5, 100) + "%";
        }
        else if (data.phase === "scanning") {
            progressBar.style.background = "#facc15";
            progressBar.style.width = Math.min(data.vulns.length * 10, 100) + "%";
        }
        else if (data.phase === "stored-analysis") {
            progressBar.style.background = "#2dd4bf";
            progressBar.style.width = Math.min(data.vulns.length * 15, 100) + "%";
        }
        else if (data.phase === "dom-analysis") {
            progressBar.style.background = "#a855f7";
            progressBar.style.width = Math.min(data.vulns.length * 20, 100) + "%";
        }
        else if (data.phase === "ai") {
            progressBar.style.background = "#ff1493";
            progressBar.style.width = Math.min(data.vulns.filter(v=>v.ai_fix).length * 20, 100) + "%";
        }
        else {
            progressBar.style.width = "0%";
        }

        /// Config Attack Timeline
        if (data.phase === "crawling" && !scanActive) {
            scanStartTime = Date.now();
            scanActive = true;
        }
        if (scanActive && ["crawling","scanning","stored-analysis","dom-analysis"].includes(data.phase)) {
            const secondsElapsed = Math.floor((Date.now() - scanStartTime) / 1000);

            // Prevent duplicate second entries
            if (attackLabels.length === 0 || attackLabels[attackLabels.length - 1] !== secondsElapsed) {
                attackLabels.push(secondsElapsed);
                attackTimeline.push(data.vulns.length);

                timelineChart.data.labels = attackLabels;
                timelineChart.data.datasets[0].data = attackTimeline;
                timelineChart.update();
            }
        }

        // Freeze when done
        if (["done","idle","stopped"].includes(data.phase)) {
            scanActive = false;
        }

        // Config Attack Density
        if (scanActive && ["crawling","scanning","stored-analysis","dom-analysis"].includes(data.phase)) {
            const currentCount = data.vulns.length;
            const delta = currentCount - lastVulnCount;

            lastVulnCount = currentCount;

            const secondsElapsed = Math.floor((Date.now() - scanStartTime) / 1000);

            if (densityLabels.length === 0 || densityLabels[densityLabels.length - 1] !== secondsElapsed) {
                densityLabels.push(secondsElapsed);
                densityData.push(Math.max(delta,0));
                densityChart.data.labels = densityLabels;
                densityChart.data.datasets[0].data = densityData;
                densityChart.update();
            }
        }

        /// Real-Time Phase Transition Feedback
        const statusEl = document.getElementById("status");

        statusEl.className = "";

        if (data.phase === "crawling") statusEl.classList.add("orange");
        if (data.phase === "scanning") statusEl.classList.add("yellow");
        if (data.phase === "stored-analysis") statusEl.classList.add("cyan");
        if (data.phase === "dom-analysis") statusEl.classList.add("purple");
        if (data.phase === "ai") statusEl.classList.add("pink");
        if (data.phase === "idle") statusEl.classList.add("green");

        /// Dashboard Card Metrics
        document.getElementById("threatIndex").textContent = analytics.threat_index || 0;
        document.getElementById("critCount").textContent = sevDist.critical || 0;
        document.getElementById("highCount").textContent = sevDist.high || 0;
        document.getElementById("medCount").textContent = sevDist.medium || 0;
        document.getElementById("lowCount").textContent = sevDist.low || 0;
        document.getElementById("totalLinks").textContent = data.urls.length;
        document.getElementById("status").textContent = data.phase.toUpperCase();
        document.getElementById("timeTaken").textContent = data.elapsed ? data.elapsed + "s" : "0";
        document.getElementById("attackSurface").textContent = analytics.attack_surface;

        // Update XSS Type Distribution Chart
        typeChart.data.labels = Object.keys(typeDist);
        typeChart.data.datasets[0].data = Object.values(typeDist);
        typeChart.update();

        // Update severity chart
        severityChart.data.datasets[0].data = [
          sevDist.critical || 0,
          sevDist.high || 0,
          sevDist.medium || 0,
          sevDist.low || 0
        ];
        severityChart.update();

        /// Config Threat Gauge | Threat Index | Threat Score
        document.getElementById("threatScore").textContent = threatIndex;
        const normalized = Math.min(threatIndex,100); // Normalize to 0–100 scale for gauge
        threatGauge.data.datasets[0].data = [normalized, 100 - normalized];

        if (normalized > 75){ // Dynamic color shift
            threatGauge.data.datasets[0].backgroundColor[0] = "#dc2626";
        }
        else if (normalized > 40){
            threatGauge.data.datasets[0].backgroundColor[0] = "#facc15";
        }
        else{
            threatGauge.data.datasets[0].backgroundColor[0] = "#22c55e";
        }
        threatGauge.update();

        /// Vulnerability Endpoint Ranking
        const rankingDiv = document.getElementById("endpointRanking");
        rankingDiv.innerHTML = "";
        const endpointCounts = {};

        data.vulns.forEach(v => {
            // normalize and group endpoint + parameter
            const urlObj = new URL(v.url);
            const endpoint = urlObj.origin + urlObj.pathname;
            const param = (v.parameter || "").toLowerCase();
            const key = endpoint + "|" + param + "|" + v.vuln_type;

            if (!endpointCounts[key]) {
                endpointCounts[key] = { url:endpoint, count:0 };
            }
            endpointCounts[key].count += 1;
        });

        const sorted = Object.values(endpointCounts)
            .sort((a,b)=>b.count-a.count)
            .slice(0,5);
        sorted.forEach((item,index)=>{
            const row=document.createElement("div");
            row.style.padding = "6px";
            row.style.marginBottom = "4px";
            row.style.background = "#1e293b";
            row.style.borderRadius = "4px";

           row.innerHTML=`
           <b>#${index+1}</b> (${item.count} issues)
           <div>${item.url}</div>
           `;
           rankingDiv.appendChild(row);
        });


        ///  Heatmap
        const heatmap = document.getElementById("heatmap");
        heatmap.innerHTML = "";
        const urlCounts = {};

        data.vulns.forEach(v=>{
          const urlObj = new URL(v.url);
          const endpoint = urlObj.origin + urlObj.pathname;

          if(!urlCounts[endpoint]){
              urlCounts[endpoint] = {count:0,severity:0};
          }
          urlCounts[endpoint].count += 1;

          if(v.severity === "critical") urlCounts[endpoint].severity += 4;
          else if(v.severity === "high") urlCounts[endpoint].severity += 3;
          else if(v.severity === "medium") urlCounts[endpoint].severity += 2;
          else urlCounts[endpoint].severity += 1;
        });

        // Render blocks
        Object.entries(urlCounts).forEach(([endpoint,dataObj])=>{
          const intensity = Math.min(dataObj.severity * 15,100);
          const block = document.createElement("div");

          block.style.padding = "10px";
          block.style.borderRadius = "6px";
          block.style.background = `rgba(239,68,68,${intensity/100})`;
          block.style.fontSize = "12px";
          block.style.wordBreak = "break-all";

          block.innerHTML = `
            <div style="font-weight:bold;">${dataObj.count} issues</div>
            <div>${endpoint}</div>
          `;
          heatmap.appendChild(block);
        });


        /// Risk Score
        const riskScore = Math.min(analytics.threat_index || 0, 100);
        riskDial.data.datasets[0].data = [riskScore, 100 - riskScore]; // Update dial values

        // Determine risk score level & color
        let level = "LOW";
        let color = "#22c55e";

        if (riskScore > 75){
          level = "CRITICAL";
          color = "#dc2626";
        }
        else if (riskScore > 50){
          level = "HIGH";
          color = "#ef4444";
        }
        else if (riskScore > 25){
          level = "MEDIUM";
          color = "#facc15";
        }

        // Risk Level KPI color
        let riskLevel = "LOW";
        let riskColor = "#22c55e";

        if (threatIndex > 75) {
            riskLevel = "CRITICAL";
            riskColor = "#dc2626";
        }
        else if (threatIndex > 50) {
            riskLevel = "HIGH";
            riskColor = "#ef4444";
        }
        else if (threatIndex > 25) {
            riskLevel = "MEDIUM";
            riskColor = "#facc15";
        }

        const riskEl = document.getElementById("riskLevelKPI");
        riskEl.textContent = riskLevel.toUpperCase();
        riskEl.style.color = riskColor;

        riskDial.data.datasets[0].backgroundColor[0] = color;
        riskDial.update();

        document.getElementById("riskLevel").textContent = level;
        document.getElementById("riskLevel").style.color = color;


        ///  Live Vulnerabilities Panel
        const feed = document.getElementById("vulnFeed");

        if (!window.renderedVulns) {
            window.renderedVulns = new Set();
        }

        data.vulns.forEach(v => {
            // Safe field extraction
            const url = v.url || "";
            const endpoint = url.split("?")[0];
            const param = (v.parameter || "").toLowerCase();
            const vulnType = v.vuln_type || (v.context === "javascript" ? "DOM XSS" :
                v.context === "html" ? "Stored XSS" :
                        "Reflected XSS"
            );

            const severity = v.severity || "low";
            const context = v.context || null;

            // ignore payload mutations in URL
            const key = endpoint + "|" + param + "|" + vulnType + "|" + severity;

            if (window.renderedVulns.has(key)) return;
            window.renderedVulns.add(key);

            const entry = document.createElement("div");
            entry.className = "feed-entry";

            // Severity color bar
            entry.style.borderLeftColor =
                severity === "critical" ? "#dc2626" :
                severity === "high" ? "#ef4444" :
                severity === "medium" ? "#facc15" :
                "#22c55e";

            // Context Badge
            let contextBadge = "";

            if (context) {
                let color = "bg-gray-600";

                if(context === "javascript") color = "bg-red-600";
                if(context === "attribute") color = "bg-orange-600";
                if(context === "html") color = "bg-yellow-600";
                if(context === "url") color = "bg-blue-600";

                contextBadge = `
                    <span class="text-xs ${color} px-2 py-1 rounded ml-2">
                        ${context}
                    </span>
                `;
            }
            // Render entry
            entry.innerHTML = `
                <b>[${severity.toUpperCase()}]</b>
                ${vulnType}
                ${contextBadge}
                →
                ${url}
            `;
            feed.appendChild(entry);
            feed.scrollTop = feed.scrollHeight;
        });

        // Button State Sync
        if (data.phase === "done") {
            scanState = "idle";
            scanCompleted = true;
            updateButtons(true);
        }
        else if (data.phase === "idle") {
            scanState = "idle";
            updateButtons(false);
        }
        else if (data.phase === "paused") {
            scanState = "paused";
            scanCompleted = false;
            updateButtons(false);
        }
        else if (["crawling","scanning","stored-analysis", "dom-analysis"].includes(data.phase)) {
            scanState = "running";
            scanCompleted = false;
            updateButtons(false);
        }

        if (document.getElementById("aiSection").style.display === "block") {
        renderAIList();
        }
    };
}
connectSocket();

/// ------------------ AI Remediation Panel --------------------

function openAISection(){
    document.getElementById("aiSection").style.display = "block";
    document.getElementById("aiSection")
        .scrollIntoView({behavior:"smooth"});
    renderAIList();
}

function renderAIList(){
    const container = document.getElementById("aiVulnList");
    container.innerHTML = "";

    const seen = new Set();

    window.currentVulns.forEach((v,index)=>{

        const endpoint = v.url.split("?")[0];
        const param = (v.parameter || "").toLowerCase();
        const type = v.vuln_type || "XSS";
        const key = endpoint + "|" + param + "|" + type;

        if(seen.has(key)) return;
        seen.add(key);

        const row = document.createElement("div");
        row.style.marginBottom = "12px";
        row.style.padding = "10px";
        row.style.background = "#1e293b";
        row.style.borderRadius = "6px";

        row.innerHTML = `
            <div style="display:flex;justify-content:space-between;">
                <div>
                    <input type="checkbox"
                            value="${index}"
                            ${selectedVulns.has(index) ? "checked" : ""}
                            onchange="toggleSelection(${index}, this)">
                    <b>${v.url}</b>
                    (${v.param}) - ${v.severity}
                </div>
                <div>
                    <button class="bg-pink-500 px-3 py-2 mt-2 mr-2 rounded-xl text-black font-bold hover:bg-pink-100"
                        onclick="toggleCard(${index})">
                        Toggle
                    </button>
                    <button
                     class="bg-green-500 px-3 py-2 mt-2 rounded-xl text-black font-bold hover:bg-green-100"
                     onclick="generateSingleAI(${index}, this)"
                     ${generatingVulns.has(index) ? "disabled" : ""}>
                     ${generatingVulns.has(index) ? "Generating..." : "Generate Fix"}
                    </button>
                </div>
            </div>
            ${v.ai_fix ? (() => {

            const s = parseAISections(v.ai_fix);

            return `
        <div id="cardBody-${index}" style="background:#020617;padding:12px;border-radius:8px;margin-top:8px;display:${collapsedCards.has(index) ? "none" : "block"}">
        <div style="color:#38bdf8;font-size:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
        <span>Generated in ${v.ai_time || "?"} seconds</span>
        </div>
        <div>
        <b style="color:#22c55e;">Explanation</b>
        <p>${s.explanation}</p>
        </div>
        <div style="margin-top:8px;">
        <b style="color:#22c55e;">Impact</b>
        <p>${s.impact}</p>
        </div>
        <div style="margin-top:8px;">
        <b style="color:#22c55e;">Secure Fix</b>
        <p>${s.fix}</p>
        </div>
        <div style="margin-top:8px;">
        <b style="color:#22c55e;">Secure Code Example</b>
        <pre style="background:#020617;padding:6px;border-radius:4px;">
        ${s.code}
        </pre>
        </div>
        <div style="margin-top:8px;">
        <b style="color:#22c55e;">Prevention Checklist</b>
        <p>${s.checklist}</p>
        </div>
        <button onclick="copyFix(${index})"
        class="bg-gray-500 px-2 py-1 mt-2 rounded-xl text-black font-bold hover:bg-gray-100">
        Copy
        </button>
        </div>
        `;
        })() : ""}
        `;
        container.appendChild(row);
    });
}

function copyFix(index){
    const text = document.getElementById(`fixText-${index}`).innerText;
    navigator.clipboard.writeText(text);
    alert("Fix copied to clipboard");
}

function showSpinner(){
    const panel = document.getElementById("aiSection");
    panel.insertAdjacentHTML(
        "beforeend",
        `<div id="aiSpinner" class="spinner"></div>`
    );
}

function hideSpinner(){
    const s = document.getElementById("aiSpinner");
    if (s) s.remove();
}

function generateSingleAI(index, btn){

    generatingVulns.add(index)

    btn.disabled = true;
    btn.innerText = "Generating...";

    showSpinner();

    fetch("/generate_ai",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify([index])
    })
    .then(res=>res.json())
    .then(data=>{
        hideSpinner();
        generatingVulns.delete(index)
        renderAIList()
    })
    .catch(()=>{
        hideSpinner();
        btn.disabled = false;
        btn.innerText = "Generate Fix";
    });
}

function generateSelectedAI(btn){
    btn.disabled = true;
    btn.innerText = "Generating...";

    const checkboxes = document.querySelectorAll("#aiVulnList input:checked");
    const selected = Array.from(selectedVulns)

    if (!selected.length){
        btn.disabled = false;
        btn.innerText = "Generate Fix";
        return;
    }
    showSpinner();

    fetch("/generate_ai",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(selected)
    })
    .then(res=>res.json())
    .then(data=>{
        hideSpinner();
        btn.disabled = false;
        btn.innerText = "Generate Fix";
    })
    .catch(()=>{
        hideSpinner();
        btn.disabled = false;
        btn.innerText = "Generate Fix";
    });
}

function generateTop3(btn){
    btn.disabled = true;
    btn.innerText = "Generating...";

    const top3 = window.currentVulns
        .slice(0,3)
        .map((_,i)=>i);

    if (!top3.length){
        btn.disabled = false;
        btn.innerText = "Generate Top 3";
        return;
    }
    showSpinner();

    fetch("/generate_ai",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(top3)
    })
    .then(res=>res.json())
    .then(data=>{
        hideSpinner();
        btn.disabled = false;
        btn.innerText = "Generate Top 3";
    })
    .catch(()=>{
        hideSpinner();
        btn.disabled = false;
        btn.innerText = "Generate Top 3";
    });
}

function toggleCard(index){
    const body = document.getElementById(`cardBody-${index}`);

    if(!body) return;

    const collapsed = collapsedCards.has(index);

    if(collapsed){
        collapsedCards.delete(index);
        body.style.display = "block";
    }else{
        collapsedCards.add(index);
        body.style.display = "none";
    }
}

function toggleSelection(index, cb){
    if(cb.checked)
        selectedVulns.add(index)
    else
        selectedVulns.delete(index)
}

function parseAISections(text){
    const sections = {
        explanation:"",
        impact:"",
        fix:"",
        code:"",
        checklist:""
    };
    const parts = text.split("###");

    parts.forEach(p=>{
        const lower = p.toLowerCase();

        if(lower.includes("explanation"))
            sections.explanation = p.replace(/explanation/i,"").trim();

        if(lower.includes("impact"))
            sections.impact = p.replace(/impact/i,"").trim();

        if(lower.includes("secure fix"))
            sections.fix = p.replace(/secure fix/i,"").trim();

        if(lower.includes("secure code"))
            sections.code = p.replace(/secure code example/i,"").trim();

        if(lower.includes("prevention"))
            sections.checklist = p.replace(/prevention checklist/i,"").trim();
    });
    return sections;
}
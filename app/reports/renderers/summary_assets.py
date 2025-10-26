# app/reports/renderers/summary_assets.py

CSS_STYLES = """
/* Bonus: upgrade general colors at :root */
:root {
  --bg: #f0f2f5;
  --primary: #2c3e50;
  --secondary: #3d566e;
  --accent: #3498db;
  --low: #2ecc71;
  --med: #f39c12;
  --high: #e74c3c;
  --text: #2d3436;
  --hover: #ecf0f1;
  --transition: 0.3s;
}

/* reset styles */
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  padding: 2rem;
  line-height: 1.5;
}

header, main, footer {
  max-width: 1200px;
  margin: auto;
}

h1 {
  text-align: center;
  color: var(--primary);
  margin-bottom: 1rem;
}

.stats {
  text-align: center;
  margin-bottom: 1.5rem;
}

.chart-wrapper {
  max-width: 350px;
  margin: 0 auto 2rem;
  background: #fff;
  padding: 1rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  height: 300px;
}

.filter-container {
  text-align: center;
  margin-bottom: 1rem;
}

.filter-input {
  padding: 0.5rem;
  max-width: 400px;
  width: 100%;
  border: 1px solid var(--secondary);
  border-radius: 4px;
  transition: border-color var(--transition);
}

.filter-input:focus {
  outline: none;
  border-color: var(--accent);
}

/* Step 2: Add visual effects to links */
a {
  text-decoration: none; /* remove underline */
  color: var(--primary); /* link color */
  transition: color var(--transition); /* smooth transition */
}
a:hover {
  color: var(--accent);      /* accent color on hover */
  transform: scale(1.05);     /* subtle zoom effect */
}

/* Step 3: Stripe table rows and round table corners */
table {
  width: 100%;
  border-collapse: collapse;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  border-radius: 8px; /* rounded corners */
  overflow: hidden;   /* ensure corners clip */
}
th, td {
  padding: 0.75rem 1rem;
  text-align: left;
}
th {
  background: var(--secondary);
  color: #fff;
}
tbody tr:nth-child(even) {
  background-color: #f9f9f9; /* striped effect */
}
tbody tr {
  background: #fff;
  transition: background var(--transition);
}
tbody tr:hover {
  background: var(--hover);
}

.badge {
  display: inline-block;
  padding: 0.25rem 0.6rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 600;
  transition: transform var(--transition);
}
.badge.clean      { background: var(--low); }
.badge.suspicious { background: var(--high); }
.badge:hover      { transform: scale(1.05); }

.progress-container {
  background: #e0e6eb;
  border-radius: 4px;
  overflow: hidden;
  height: 0.75rem;
  margin-bottom: 0.25rem;
}
.progress-bar.low  { background: var(--low); }
.progress-bar.med  { background: var(--med); }
.progress-bar.high { background: var(--high); }

footer p {
  text-align: center;
  padding: 1rem;
  color: var(--secondary);
}
"""

JS_SCRIPTS = """
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
(() => {
  const renderChart = (passed, failed) => {
    const ctx = document.getElementById("pieChart").getContext("2d");
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Passed", "Failed"],
        datasets: [{
          data: [passed, failed],
          backgroundColor: ["#27ae60", "#e74c3c"], // Step 1: fix pie chart colors to real hex codes
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        animation: {            // Step 4: add rotation animation
          animateRotate: true,
          duration: 1000
        },
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 12 } }
        }
      }
    });
  };

  const filterTable = () => {
    const query = document.getElementById("filterInput").value.toLowerCase();
    document.querySelectorAll("tbody tr").forEach(tr => {
      const url = tr.querySelector("td.url").textContent.toLowerCase();
      tr.style.display = url.includes(query) ? "" : "none";
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    const passed = {{passed}}, failed = {{failed}};
    renderChart(passed, failed);
    document.getElementById("filterInput")
            .addEventListener("input", filterTable);
  });
})();
</script>
"""

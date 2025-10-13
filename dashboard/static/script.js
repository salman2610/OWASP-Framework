document.addEventListener("DOMContentLoaded", () => {
  const trendData = window.trendData || [];
  const owaspCategories = window.owaspCategories || {};

  // Trend Chart
  const ctxTrend = document.getElementById('trendChart');
  new Chart(ctxTrend, {
    type: 'line',
    data: {
      labels: trendData.map(d => d.timestamp.split('T')[0]),
      datasets: [
        { label: 'High', data: trendData.map(d => d.high), borderColor: '#ef4444', fill: false },
        { label: 'Medium', data: trendData.map(d => d.medium), borderColor: '#eab308', fill: false },
        { label: 'Low', data: trendData.map(d => d.low), borderColor: '#22c55e', fill: false }
      ]
    },
    options: {
      plugins: { legend: { labels: { color: '#fff' } } },
      scales: {
        x: { ticks: { color: '#fff' } },
        y: { ticks: { color: '#fff' } }
      }
    }
  });

  // OWASP Chart
  const ctxOwasp = document.getElementById('owaspChart');
  new Chart(ctxOwasp, {
    type: 'bar',
    data: {
      labels: Object.keys(owaspCategories),
      datasets: [{
        label: 'Vulnerabilities per Category',
        data: Object.values(owaspCategories),
        backgroundColor: '#3b82f6'
      }]
    },
    options: {
      plugins: { legend: { labels: { color: '#fff' } } },
      scales: {
        x: { ticks: { color: '#fff' } },
        y: { ticks: { color: '#fff' } }
      }
    }
  });

  // PDF Export
  document.getElementById('downloadPDF').addEventListener('click', () => {
    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });
    pdf.html(document.body, {
      callback: () => pdf.save('OWASP_Framework_Dashboard.pdf'),
      html2canvas: { scale: 0.6 }
    });
  });
});

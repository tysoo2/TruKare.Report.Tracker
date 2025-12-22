using System.Text;
using Microsoft.AspNetCore.Mvc;
using TruKare.Reports.Services;

namespace TruKare.Reports.Controllers;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    private readonly IReportVaultService _reportVaultService;

    public AdminController(IReportVaultService reportVaultService)
    {
        _reportVaultService = reportVaultService;
    }

    [HttpGet("dashboard-data")]
    public IActionResult GetDashboardData()
    {
        var data = _reportVaultService.GetDashboardSummary();
        return Ok(data);
    }

    [HttpGet("dashboard-view")]
    public ContentResult GetDashboardView()
    {
        var html = new StringBuilder();
        html.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Report Admin Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        h1 { margin-bottom: 0.5rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
        .card { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        .small { color: #666; font-size: 0.9rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
        th, td { text-align: left; padding: 0.35rem; border-bottom: 1px solid #f0f0f0; }
    </style>
</head>
<body>
    <h1>Report Dashboard (Stub)</h1>
    <p class="small">This lightweight view is backed by the public APIs and can be embedded into an external dashboard.</p>
    <div class="grid">
        <div class="card">
            <h3>Totals</h3>
            <div id="totals">Loading...</div>
        </div>
        <div class="card">
            <h3>Active Locks</h3>
            <table id="lockedByTable">
                <thead><tr><th>User</th><th>Locked</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
    <div class="card" style="margin-top:1rem;">
        <h3>By Customer</h3>
        <table id="customerTable">
            <thead><tr><th>Customer</th><th>In Progress</th><th>Done</th><th>Locked</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <script>
        async function loadDashboard() {
            const response = await fetch('/reports/dashboard');
            const data = await response.json();
            document.getElementById('totals').innerText = `In Progress: ${data.totals.inProgress} | Done: ${data.totals.done} | Archived: ${data.totals.archived} | Locked: ${data.totals.locked}`;

            const lockedBody = document.querySelector('#lockedByTable tbody');
            lockedBody.innerHTML = '';
            data.byLockedBy.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${item.key}</td><td>${item.locked}</td>`;
                lockedBody.appendChild(row);
            });

            const customerBody = document.querySelector('#customerTable tbody');
            customerBody.innerHTML = '';
            data.byCustomer.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${item.key}</td><td>${item.inProgress}</td><td>${item.done}</td><td>${item.locked}</td>`;
                customerBody.appendChild(row);
            });
        }

        loadDashboard();
    </script>
</body>
</html>
""");

        return Content(html.ToString(), "text/html", Encoding.UTF8);
    }
}

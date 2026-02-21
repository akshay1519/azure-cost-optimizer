# ⚡ Azure Cost Optimizer

**Save up to 30% on your Azure bill.** Scan your Azure subscription for idle VMs, oversized resources, orphaned disks, compliance gaps, and security anomalies — all in one tool.

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![GitHub Sponsors](https://img.shields.io/badge/sponsor-♥-ea4aaa.svg)](https://github.com/sponsors/AkshaykumarGlasswala)

---

## 🎯 What It Does

| Check | What It Finds | Typical Savings |
|-------|--------------|-----------------|
| 🔴 Idle VMs | VMs with <5% CPU for 14+ days | $70–$560/month per VM |
| 🟡 Oversized VMs | VMs using <10% CPU that can downsize | $70–$280/month per VM |
| 🟡 Orphaned Disks | Unattached managed disks | $20–$270/month per disk |
| 🔵 Unused Public IPs | IPs not attached to any resource | $3.65/month each |
| 🔵 Old Snapshots | Snapshots older than 30 days | $0.05/GB/month |
| 🟡 Stopped VMs + Premium Disks | Deallocated VMs still paying for premium storage | 60% of disk cost |

Plus:
- **Compliance Module** — Collects Azure Policy evidence, generates audit-ready reports (SOC2, ISO 27001)
- **Security Module** — Queries Azure Sentinel/Log Analytics for brute-force attempts, privilege escalation, and anomalies

---

## 📊 Example Output

```
======================================================================
  AZURE COST OPTIMIZATION REPORT
======================================================================
  Subscription: Contoso Production
  Total Findings: 8
  Estimated Monthly Waste: $1,247.53
  Estimated Annual Waste:  $14,970.36

  BREAKDOWN BY CATEGORY
  ────────────────────────────────
  Idle Vm: 2 finding(s) — $560.64/month
  Oversized Vm: 2 finding(s) — $210.24/month
  Unattached Disk: 2 finding(s) — $213.42/month
  Unused Public Ip: 1 finding(s) — $3.65/month
  Old Snapshot: 1 finding(s) — $19.58/month

  #1 [HIGH] api-server-01
     Category: Idle Vm
     Current Cost: $280.32/month
     Potential Savings: $280.32/month
     Recommendation: Deallocate or delete — avg CPU 1.8% over 14 days.
======================================================================
```

Reports are also generated as **JSON**, **HTML**, and **CSV**. See [examples/](examples/) for sample outputs.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Azure CLI logged in (`az login`) or a service principal configured
- Reader access to the target Azure subscription

### Install

```bash
git clone https://github.com/AkshaykumarGlasswala/azure-cost-optimizer.git
cd azure-cost-optimizer
pip install -r requirements.txt
```

### Run a Cost Scan

```bash
# Scan for idle/oversized resources
python -m analyzer.cli scan --subscription-id "YOUR_SUBSCRIPTION_ID"

# Save reports to a directory
python -m analyzer.cli scan -s "YOUR_SUB_ID" -o reports/ -f json html csv

# Customize thresholds
python -m analyzer.cli scan -s "YOUR_SUB_ID" --idle-cpu-threshold 3.0 --idle-days 7
```

### Run a Compliance Audit

```bash
python -m analyzer.cli compliance -s "YOUR_SUBSCRIPTION_ID" -o reports/
```

### Run a Security Scan

```bash
python -m analyzer.cli security -w "YOUR_LOG_ANALYTICS_WORKSPACE_ID" -o reports/
```

### Run Everything

```bash
python -m analyzer.cli all -s "YOUR_SUB_ID" -w "YOUR_WORKSPACE_ID"
```

---

## 🌐 Web Dashboard (SaaS)

A hosted version is available with automated daily scans and email reports.

### Run Locally

```bash
# Set environment variables
export FLASK_SECRET_KEY="your-secret-key"
export STRIPE_SECRET_KEY="sk_test_..."
export STRIPE_PUBLISHABLE_KEY="pk_test_..."

# Start the web app
python webapp/app.py
```

Then open http://localhost:5000

### Deploy to Azure App Service

```bash
az webapp up --name azure-cost-optimizer --resource-group rg-optimizer --runtime "PYTHON:3.11"
```

---

## 💰 Pricing

| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0 | 1 manual scan, CLI access, all report formats |
| **Basic** | $20/month | Unlimited scans, weekly automation, email reports, compliance module |
| **Pro** | $50/month | Everything in Basic + daily scans, security module, API access, priority support |

---

## ❤️ Sponsor This Project

If this tool saves your team money, consider sponsoring development:

| Tier | Price | Benefits |
|------|-------|----------|
| Community | $5/month | Name in README, early access to updates |
| Priority | $20/month | Priority feature requests, early access |
| SaaS Access | $50/month | Hosted dashboard included, priority support |

👉 [**Become a Sponsor**](https://github.com/sponsors/AkshaykumarGlasswala)

---

## 🧪 Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## 📁 Project Structure

```
azure-cost-optimizer/
├── analyzer/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # python -m analyzer entry point
│   ├── cli.py               # CLI interface (argparse)
│   ├── scanner.py           # Core VM/disk/IP/snapshot scanner
│   ├── reporter.py          # Report generation (JSON/HTML/CSV/console)
│   ├── compliance.py        # Azure Policy compliance auditor
│   └── security.py          # Azure Sentinel/Log Analytics scanner
├── webapp/
│   ├── app.py               # Flask web app + Stripe billing
│   ├── templates/           # Jinja2 HTML templates
│   └── static/              # CSS + JS assets
├── tests/
│   ├── test_scanner.py      # Scanner unit tests
│   ├── test_reporter.py     # Reporter unit tests
│   └── test_webapp.py       # Web app integration tests
├── examples/
│   ├── sample_cost_report.json
│   ├── sample_compliance_report.json
│   └── sample_security_report.json
├── .github/
│   ├── FUNDING.yml          # GitHub Sponsors config
│   ├── workflows/ci.yml     # CI/CD pipeline
│   └── ISSUE_TEMPLATE/      # Bug report & feature request templates
├── requirements.txt
├── setup.py
├── LICENSE                  # MIT License
└── README.md
```

---

## 🔧 Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `FLASK_SECRET_KEY` | Flask session secret | `dev-secret-...` |
| `STRIPE_SECRET_KEY` | Stripe API secret key | — |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key | — |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret | — |
| `STRIPE_PRICE_BASIC` | Stripe Price ID for Basic plan | — |
| `STRIPE_PRICE_PRO` | Stripe Price ID for Pro plan | — |
| `BASE_URL` | Base URL for the web app | `http://localhost:5000` |
| `PORT` | Web server port | `5000` |

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Akshaykumar Glasswala**

- GitHub: [@AkshaykumarGlasswala](https://github.com/AkshaykumarGlasswala)
- Sponsor: [github.com/sponsors/AkshaykumarGlasswala](https://github.com/sponsors/AkshaykumarGlasswala)

---

*Built with ❤️ to help teams stop overpaying for Azure.*

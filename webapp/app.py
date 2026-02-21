"""
Azure Cost Optimizer - Web Application (Flask + Stripe SaaS)

Features:
- Free tier: Run one-time manual scan
- Paid tier: Automated daily/weekly scans + email reports
- Stripe Checkout for subscriptions
- Dashboard with scan results
"""

import json
import os
import logging
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import stripe
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, session, flash, send_file,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-in-production")

# Stripe config
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_BASIC = os.environ.get("STRIPE_PRICE_BASIC", "")      # $20/month
STRIPE_PRICE_PRO = os.environ.get("STRIPE_PRICE_PRO", "")          # $50/month
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

logger = logging.getLogger(__name__)

# In-memory store (replace with database in production)
USERS = {}       # email -> {plan, stripe_customer_id, subscription_id, scans:[]}
SCAN_RESULTS = {}  # scan_id -> ScanResult dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_current_user():
    """Get current user from session."""
    email = session.get("user_email")
    if email and email in USERS:
        return USERS[email]
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_user_plan(email: str) -> str:
    """Get the plan for a user."""
    user = USERS.get(email)
    return user.get("plan", "free") if user else "free"


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Landing page."""
    return render_template("index.html")


@app.route("/pricing")
def pricing():
    """Pricing page."""
    return render_template("pricing.html", stripe_key=STRIPE_PUBLISHABLE_KEY)


# ---------------------------------------------------------------------------
# Auth (simplified — replace with Azure AD / OAuth in production)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email:
            if email not in USERS:
                USERS[email] = {
                    "email": email,
                    "plan": "free",
                    "stripe_customer_id": None,
                    "subscription_id": None,
                    "scans": [],
                }
            session["user_email"] = email
            flash(f"Welcome, {email}!", "success")
            return redirect(url_for("dashboard"))
        flash("Please enter a valid email.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_email", None)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    email = session["user_email"]
    user = USERS[email]
    scans = user.get("scans", [])
    return render_template("dashboard.html", user=user, scans=scans)


# ---------------------------------------------------------------------------
# Scan endpoint (free: 1 manual, paid: unlimited)
# ---------------------------------------------------------------------------
@app.route("/scan", methods=["POST"])
@login_required
def run_scan():
    email = session["user_email"]
    user = USERS[email]
    plan = user.get("plan", "free")

    subscription_id = request.form.get("subscription_id", "").strip()
    if not subscription_id:
        flash("Please enter your Azure Subscription ID.", "error")
        return redirect(url_for("dashboard"))

    # Free tier: max 1 scan
    if plan == "free" and len(user.get("scans", [])) >= 1:
        flash("Free tier allows 1 scan. Upgrade for unlimited scans.", "warning")
        return redirect(url_for("pricing"))

    try:
        from analyzer.scanner import AzureScanner
        from analyzer.reporter import ReportGenerator

        scanner = AzureScanner(subscription_id=subscription_id)
        result = scanner.scan_all()
        reporter = ReportGenerator(result)

        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{email.split('@')[0]}"

        # Store result
        report_data = json.loads(reporter.generate_json_report())
        SCAN_RESULTS[scan_id] = report_data
        user.setdefault("scans", []).append({
            "scan_id": scan_id,
            "subscription_id": subscription_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(result.findings),
            "monthly_waste": round(result.total_monthly_waste, 2),
        })

        flash(
            f"Scan complete! Found {len(result.findings)} issues, "
            f"${result.total_monthly_waste:,.2f}/month potential savings.",
            "success",
        )
        return redirect(url_for("scan_detail", scan_id=scan_id))

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        flash(f"Scan failed: {str(e)}", "error")
        return redirect(url_for("dashboard"))


@app.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    report = SCAN_RESULTS.get(scan_id)
    if not report:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard"))
    return render_template("scan_detail.html", report=report, scan_id=scan_id)


@app.route("/scan/<scan_id>/download/<fmt>")
@login_required
def download_report(scan_id, fmt):
    """Download scan report in various formats."""
    report_data = SCAN_RESULTS.get(scan_id)
    if not report_data:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard"))

    if fmt == "json":
        content = json.dumps(report_data, indent=2)
        mimetype = "application/json"
        filename = f"{scan_id}.json"
    else:
        flash("Unsupported format.", "error")
        return redirect(url_for("scan_detail", scan_id=scan_id))

    from io import BytesIO
    buffer = BytesIO(content.encode())
    return send_file(buffer, mimetype=mimetype, as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# Stripe Checkout & Billing
# ---------------------------------------------------------------------------
@app.route("/checkout/<plan>")
@login_required
def checkout(plan):
    """Create Stripe Checkout session."""
    email = session["user_email"]

    price_map = {
        "basic": STRIPE_PRICE_BASIC,
        "pro": STRIPE_PRICE_PRO,
    }

    price_id = price_map.get(plan)
    if not price_id:
        flash("Invalid plan.", "error")
        return redirect(url_for("pricing"))

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            customer_email=email,
            success_url=f"{BASE_URL}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/pricing",
            metadata={"plan": plan, "email": email},
        )
        return redirect(checkout_session.url)
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        flash("Payment error. Please try again.", "error")
        return redirect(url_for("pricing"))


@app.route("/checkout/success")
@login_required
def checkout_success():
    session_id = request.args.get("session_id")
    if session_id:
        try:
            cs = stripe.checkout.Session.retrieve(session_id)
            email = cs.metadata.get("email", session.get("user_email"))
            plan = cs.metadata.get("plan", "basic")

            if email in USERS:
                USERS[email]["plan"] = plan
                USERS[email]["stripe_customer_id"] = cs.customer
                USERS[email]["subscription_id"] = cs.subscription

            flash(f"Upgraded to {plan.title()} plan! Enjoy unlimited scans.", "success")
        except Exception as e:
            logger.error(f"Error retrieving checkout session: {e}")

    return redirect(url_for("dashboard"))


@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events."""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({"error": "Invalid signature"}), 400

    if event["type"] == "customer.subscription.deleted":
        sub = event["data"]["object"]
        # Find user and downgrade
        for email, user in USERS.items():
            if user.get("subscription_id") == sub["id"]:
                user["plan"] = "free"
                user["subscription_id"] = None
                logger.info(f"Downgraded {email} to free plan")
                break

    elif event["type"] == "customer.subscription.updated":
        sub = event["data"]["object"]
        # Could handle plan changes here
        pass

    return jsonify({"status": "ok"})


@app.route("/billing")
@login_required
def billing():
    """Redirect to Stripe Customer Portal."""
    email = session["user_email"]
    user = USERS.get(email)

    if not user or not user.get("stripe_customer_id"):
        flash("No active subscription found.", "warning")
        return redirect(url_for("pricing"))

    try:
        portal = stripe.billing_portal.Session.create(
            customer=user["stripe_customer_id"],
            return_url=f"{BASE_URL}/dashboard",
        )
        return redirect(portal.url)
    except stripe.error.StripeError as e:
        logger.error(f"Billing portal error: {e}")
        flash("Could not open billing portal.", "error")
        return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# API endpoints (for automation / integrations)
# ---------------------------------------------------------------------------
@app.route("/api/v1/scan", methods=["POST"])
def api_scan():
    """API endpoint for programmatic scans."""
    api_key = request.headers.get("X-API-Key", "")
    # In production, validate API key against database
    if not api_key:
        return jsonify({"error": "Missing API key"}), 401

    data = request.get_json()
    subscription_id = data.get("subscription_id")
    if not subscription_id:
        return jsonify({"error": "subscription_id required"}), 400

    try:
        from analyzer.scanner import AzureScanner
        from analyzer.reporter import ReportGenerator

        scanner = AzureScanner(subscription_id=subscription_id)
        result = scanner.scan_all()
        reporter = ReportGenerator(result)

        return jsonify(json.loads(reporter.generate_json_report()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/health")
def api_health():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)

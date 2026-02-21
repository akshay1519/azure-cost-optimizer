/* Azure Cost Optimizer - Main JS */

document.addEventListener('DOMContentLoaded', function () {
    // Auto-dismiss flash messages after 5 seconds
    document.querySelectorAll('.alert').forEach(function (alert) {
        setTimeout(function () {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.5s ease';
            setTimeout(function () { alert.remove(); }, 500);
        }, 5000);
    });

    // Scan form loading state
    var scanForm = document.querySelector('.scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function () {
            var btn = scanForm.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Scanning... (this may take a few minutes)';
                btn.style.opacity = '0.7';
            }
        });
    }

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});

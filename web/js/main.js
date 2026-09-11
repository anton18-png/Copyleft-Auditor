/* ═══════════════════════════════════════════════════════════════
   COPYLEFT AUDITOR PRO — сайт-презентация (blue cyberpunk)
   ═══════════════════════════════════════════════════════════════ */

'use strict';

/* ── Мобильное меню ─────────────────────────────────────────── */
const burger = document.getElementById('burger');
const navLinks = document.getElementById('navLinks');

burger.addEventListener('click', () => {
    navLinks.classList.toggle('open');
});

navLinks.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
        navLinks.classList.remove('open');
    });
});

/* ── Печатающийся заголовок в Hero ──────────────────────────── */
const typingEl = document.getElementById('typing');
const phrases = ['ДЛЯ КОДА', 'ВАШЕГО РЕПО', 'AGPL-3.0', 'ОБФУСКАЦИИ', 'OPEN SOURCE'];
let phraseIdx = 0;
let charIdx = 0;
let deleting = false;

function typeLoop() {
    const current = phrases[phraseIdx];
    if (!deleting) {
        typingEl.textContent = current.slice(0, charIdx + 1);
        charIdx++;
        if (charIdx === current.length) {
            deleting = true;
            setTimeout(() => { deleting = false; }, 2100);
            return setTimeout(typeLoop, 2600);
        }
        return setTimeout(typeLoop, 85);
    } else {
        typingEl.textContent = current.slice(0, charIdx - 1);
        charIdx--;
        if (charIdx === 0) {
            phraseIdx = (phraseIdx + 1) % phrases.length;
            return setTimeout(typeLoop, 350);
        }
        return setTimeout(typeLoop, 40);
    }
}
if (typingEl) typeLoop();

/* ── Анимированные счетчики в статистике ────────────────────── */
function animateCount(el) {
    const target = parseInt(el.dataset.count || '0', 10);
    const duration = 1400;
    const start = performance.now();

    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const value = Math.floor(progress * target);
        el.textContent = value;
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = target;
    }
    requestAnimationFrame(step);
}

const statNumbers = document.querySelectorAll('.stat-n');
const io = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
        if (entry.isIntersecting) {
            animateCount(entry.target);
            io.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });
statNumbers.forEach((n) => io.observe(n));

/* ── Появление секций при скролле ───────────────────────────── */
const revealEls = document.querySelectorAll(
    '.problem-card, .feature-card, .step, .risk-card, .report-feature, .tech-card, .faq-item, .solution-banner, .download-box'
);

const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
        if (entry.isIntersecting) {
            entry.target.classList.add('reveal', 'visible');
            revealObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.12 });

revealEls.forEach((el) => revealObserver.observe(el));

/* ── Мониторинг сетевого статуса (эстетика терминала) ───────── */
window.addEventListener('online', () => console.log('%c[NET] Соединение: ONLINE', 'color:#22ff88'));
window.addEventListener('offline', () => console.log('%c[NET] Соединение: OFFLINE', 'color:#ff3b5c'));

/* ── Навигация: подсветка активной секции ───────────────────── */
const sections = document.querySelectorAll('section[id]');
const navAnchors = document.querySelectorAll('.nav-links a[href^="#"]');

const spyObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
        if (entry.isIntersecting) {
            const id = entry.target.getAttribute('id');
            navAnchors.forEach((a) => {
                const href = a.getAttribute('href');
                a.style.color = href === `#${id}` ? '#00b4ff' : '';
                a.style.textShadow = href === `#${id}` ? '0 0 10px #00b4ff' : '';
            });
        }
    });
}, { rootMargin: '-40% 0px -55% 0px' });

sections.forEach((s) => spyObserver.observe(s));

/* ── Лента «логирование» в консоли (пасхалка) ───────────────── */
console.log('%cCOPYLEFT AUDITOR PRO', 'font-family:monospace;font-size:20px;font-weight:bold;color:#00b4ff;');
console.log('%cАнтивирус для кода · AGPL-3.0 · Anton-18 PNG', 'font-family:monospace;color:#7d92b8;');
console.log('%cМы — страховка от дурака в Open Source.', 'font-family:monospace;color:#33e0ff;');
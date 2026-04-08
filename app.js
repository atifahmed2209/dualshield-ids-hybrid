(function () {
  "use strict";

  const navbar = document.getElementById("navbar");
  const menuToggle = document.getElementById("menuToggle");
  const mobileMenu = document.getElementById("mobileMenu");
  const mobileLinks = mobileMenu ? mobileMenu.querySelectorAll("a") : [];
  const revealNodes = document.querySelectorAll(".reveal");
  const counterNodes = document.querySelectorAll(".counter");
  const barNodes = document.querySelectorAll(".bar-fill");
  const yearNode = document.getElementById("copyrightYear");
  const buildMetaNode = document.getElementById("buildMeta");
  const buildChecksumNode = document.getElementById("buildChecksum");
  const downloadExeBtn = document.getElementById("downloadExeBtn");
  const monitorStatusText = document.getElementById("monitorStatusText");
  const monitorMetaNode = document.getElementById("monitorMeta");
  const adminWarningNode = document.getElementById("adminWarning");
  const controllerStateNode = document.getElementById("controllerState");
  const captureStateNode = document.getElementById("captureState");
  const dashboardStateNode = document.getElementById("dashboardState");
  const startMonitoringBtn = document.getElementById("startMonitoringBtn");
  const stopMonitoringBtn = document.getElementById("stopMonitoringBtn");
  const liveEventsBody = document.getElementById("liveEventsBody");
  const controllerBaseUrl = "http://127.0.0.1:8010";

  if (yearNode) {
    yearNode.textContent = "(c) " + new Date().getFullYear();
  }

  initReleaseLink();
  initLiveConsole();

  function initReleaseLink() {
    if (!downloadExeBtn) return;

    const releaseUrl = downloadExeBtn.getAttribute("href") || "";
    const assetName = releaseUrl.split("/").pop() || "DualIDSGuardAgent_v3.0.zip";

    if (buildMetaNode) {
      buildMetaNode.textContent = "Portable ZIP release hosted on GitHub Releases.";
    }

    if (buildChecksumNode) {
      buildChecksumNode.textContent = "Release asset: " + assetName;
    }

    downloadExeBtn.setAttribute("href", releaseUrl);
  }

  function initLiveConsole() {
    if (!monitorStatusText || !liveEventsBody) return;

    if (startMonitoringBtn) {
      startMonitoringBtn.addEventListener("click", function () {
        postControllerAction("/start-monitoring");
      });
    }

    if (stopMonitoringBtn) {
      stopMonitoringBtn.addEventListener("click", function () {
        postControllerAction("/stop-monitoring");
      });
    }

    refreshLiveConsole();
    window.setInterval(refreshLiveConsole, 3000);
  }

  function postControllerAction(path) {
    fetch(controllerBaseUrl + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("Controller action failed");
        return response.json();
      })
      .then(function (payload) {
        applyLiveStatus(payload);
        refreshLiveConsole();
      })
      .catch(function (error) {
        applyLiveError(error);
      });
  }

  function refreshLiveConsole() {
    Promise.all([
      fetch(controllerBaseUrl + "/api/status").then(function (response) {
        if (!response.ok) throw new Error("Status unavailable");
        return response.json();
      }),
      fetch(controllerBaseUrl + "/api/events?limit=10").then(function (response) {
        if (!response.ok) throw new Error("Events unavailable");
        return response.json();
      })
    ])
      .then(function (results) {
        applyLiveStatus(results[0]);
        updateEventTable(results[1].events || []);
      })
      .catch(function (error) {
        applyLiveError(error);
      });
  }

  function applyLiveStatus(status) {
    const monitoringActive = Boolean(status.monitoring_active);
    const serviceHealth = status.service_health || {};
    const serviceReady = serviceHealth.status === "ok";

    monitorStatusText.textContent = status.status_indicator || (monitoringActive ? "🟢 Live Monitoring Active" : "⚪ Live Monitoring Stopped");

    if (monitorMetaNode) {
      monitorMetaNode.textContent = "Controller endpoint: " + controllerBaseUrl;
    }

    if (adminWarningNode) {
      adminWarningNode.textContent = status.run_as_admin_warning || "Controller ready. Live traffic and file activity are being monitored automatically.";
    }

    if (controllerStateNode) {
      controllerStateNode.textContent = monitoringActive ? "Online" : "Standby";
    }

    if (captureStateNode) {
      captureStateNode.textContent = monitoringActive ? "Automatic" : "Paused";
    }

    if (dashboardStateNode) {
      dashboardStateNode.textContent = serviceReady ? "Connected" : "Waiting";
    }
  }

  function applyLiveError(error) {
    if (monitorStatusText) {
      monitorStatusText.textContent = "Controller offline";
    }
    if (adminWarningNode) {
      adminWarningNode.textContent = "Open the packaged app to start the localhost controller and live monitoring stack.";
    }
    if (controllerStateNode) {
      controllerStateNode.textContent = "Offline";
    }
    if (captureStateNode) {
      captureStateNode.textContent = "Unavailable";
    }
    if (dashboardStateNode) {
      dashboardStateNode.textContent = "Retrying";
    }
    if (liveEventsBody) {
      liveEventsBody.innerHTML = '<tr><td colspan="7">Local controller not available. Start the packaged app and try again.</td></tr>';
    }
  }

  function updateEventTable(events) {
    if (!liveEventsBody) return;
    if (!events.length) {
      liveEventsBody.innerHTML = '<tr><td colspan="7">No live detections yet. Start monitoring and add network or file activity to generate events.</td></tr>';
      return;
    }

    liveEventsBody.innerHTML = events
      .map(function (event) {
        const detectionType = escapeHtml(event.detection_type || "Unknown");
        const statusText = escapeHtml(event.status || "Unknown");
        const attackType = escapeHtml(event.attack_type || "Unknown");
        const originalFileName = escapeHtml(event.original_file_name || event.file_name || fileNameFromPath(event.file_path) || "-");
        const pcapFileName = escapeHtml(event.pcap_file_name || fileNameFromPath(event.pcap_path) || "-");
        const source = escapeHtml(event.source || "unknown");
        const timestamp = escapeHtml(formatTimestamp(event.timestamp_utc));
        const pillClass = statusClass(statusText);

        return (
          "<tr>" +
          "<td>" + timestamp + "</td>" +
          "<td>" + detectionType + "</td>" +
          '<td><span class="event-pill ' + pillClass + '">' + statusText + "</span></td>" +
          "<td>" + attackType + "</td>" +
          "<td>" + originalFileName + "</td>" +
          "<td>" + pcapFileName + "</td>" +
          "<td>" + source + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function statusClass(statusText) {
    const value = statusText.toLowerCase();
    if (value.indexOf("benign") !== -1) return "benign";
    if (value.indexOf("suspicious") !== -1) return "warning";
    if (value.indexOf("warn") !== -1) return "warning";
    if (value.indexOf("fail") !== -1 || value.indexOf("mal") !== -1 || value.indexOf("attack") !== -1) return "malicious";
    return "info";
  }

  function formatTimestamp(timestamp) {
    if (!timestamp) return "Unknown";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return timestamp;
    return date.toLocaleString();
  }

  function fileNameFromPath(pathValue) {
    if (!pathValue) return "";
    const normalized = String(pathValue).replace(/\\/g, "/");
    const parts = normalized.split("/");
    return parts[parts.length - 1] || "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function onScroll() {
    if (!navbar) return;
    if (window.scrollY > 20) {
      navbar.classList.add("scrolled");
    } else {
      navbar.classList.remove("scrolled");
    }
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  if (menuToggle && mobileMenu) {
    menuToggle.addEventListener("click", function () {
      const isOpen = mobileMenu.classList.toggle("open");
      menuToggle.classList.toggle("active", isOpen);
      menuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
    mobileLinks.forEach(function (link) {
      link.addEventListener("click", function () {
        mobileMenu.classList.remove("open");
        menuToggle.classList.remove("active");
        menuToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  if ("IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: "0px 0px -5% 0px" }
    );

    revealNodes.forEach(function (node) {
      revealObserver.observe(node);
    });

    const metricObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          const target = entry.target;
          if (target.classList.contains("counter")) {
            animateCounter(target);
          }
          if (target.classList.contains("bar-fill")) {
            const width = target.getAttribute("data-width") || "0";
            target.style.width = width + "%";
          }
          metricObserver.unobserve(target);
        });
      },
      { threshold: 0.4 }
    );

    counterNodes.forEach(function (node) {
      metricObserver.observe(node);
    });
    barNodes.forEach(function (node) {
      metricObserver.observe(node);
    });
  } else {
    revealNodes.forEach(function (node) {
      node.classList.add("visible");
    });
    barNodes.forEach(function (node) {
      const width = node.getAttribute("data-width") || "0";
      node.style.width = width + "%";
    });
    counterNodes.forEach(function (node) {
      const target = Number(node.getAttribute("data-target") || "0");
      const suffix = node.getAttribute("data-suffix") || "";
      const precision = Number(node.getAttribute("data-precision") || (target % 1 !== 0 ? 2 : 0));
      node.textContent = target.toFixed(precision) + suffix;
    });
  }

  function animateCounter(node) {
    if (node.dataset.done === "true") return;
    node.dataset.done = "true";

    const target = Number(node.getAttribute("data-target") || "0");
    const suffix = node.getAttribute("data-suffix") || "";
    const precision = Number(node.getAttribute("data-precision") || (target % 1 !== 0 ? 2 : 0));
    const duration = 1400;
    const startTs = performance.now();

    function update(now) {
      const progress = Math.min((now - startTs) / duration, 1);
      const value = target * progress;
      node.textContent = value.toFixed(precision) + suffix;
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        node.textContent = target.toFixed(precision) + suffix;
      }
    }

    requestAnimationFrame(update);
  }

  initParticles();

  function initParticles() {
    const canvas = document.getElementById("particleCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId = 0;
    const particles = [];

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }

    function resetParticles() {
      particles.length = 0;
      const count = Math.max(44, Math.min(120, Math.round(window.innerWidth / 18)));
      for (let i = 0; i < count; i += 1) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.3,
          vy: (Math.random() - 0.5) * 0.3,
          size: Math.random() * 2 + 0.5,
          opacity: Math.random() * 0.45 + 0.1,
        });
      }
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (let i = 0; i < particles.length; i += 1) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = "hsla(180, 100%, 50%, " + p.opacity + ")";
        ctx.fill();

        for (let j = i + 1; j < particles.length; j += 1) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = "hsla(180, 100%, 50%, " + (0.06 * (1 - dist / 120)) + ")";
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      animationId = requestAnimationFrame(draw);
    }

    resize();
    resetParticles();
    draw();

    window.addEventListener("resize", function () {
      resize();
      resetParticles();
    });

    window.addEventListener("beforeunload", function () {
      cancelAnimationFrame(animationId);
    });
  }
})();


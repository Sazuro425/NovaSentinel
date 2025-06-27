// Données simulées basées sur le fichier JSON existant
const scanData = {
  timestamp: 1750955801,
  network: {
    ip: "192.168.1.106",
    interface: "ens18",
    gateway: "192.168.1.254",
    dns: ["192.168.1.254"],
    dhcp: "",
    active_hosts: 7,
  },
  hosts: [
    {
      ip: "192.168.1.1",
      services: [
        {
          port: "53/tcp",
          service: "domain",
          product: "Simple DNS Plus",
          version: "",
          cves: [],
        },
        {
          port: "88/tcp",
          service: "kerberos-sec",
          product: "Microsoft Windows Kerberos",
          version: "",
          cves: [],
        },
        {
          port: "389/tcp",
          service: "ldap",
          product: "Microsoft Windows Active Directory LDAP",
          version: "",
          cves: [],
        },
      ],
    },
    {
      ip: "192.168.1.101",
      services: [
        {
          port: "22/tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1 Debian 2+deb12u5",
          cves: [
            "CVE-2023-38408",
            "CVE-2023-28531",
            "CVE-2024-6387",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-48795",
            "CVE-2023-51384",
            "CVE-2025-32728",
          ],
        },
        {
          port: "80/tcp",
          service: "http",
          product: "nginx",
          version: "1.27.5",
          cves: [],
        },
      ],
    },
    {
      ip: "192.168.1.102",
      services: [
        {
          port: "22/tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1 Debian 2+deb12u6",
          cves: [
            "CVE-2023-38408",
            "CVE-2023-28531",
            "CVE-2024-6387",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-48795",
            "CVE-2023-51384",
            "CVE-2025-32728",
          ],
        },
      ],
    },
    {
      ip: "192.168.1.106",
      services: [
        {
          port: "22/tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1 Debian 2+deb12u6",
          cves: [
            "CVE-2023-38408",
            "CVE-2023-28531",
            "CVE-2024-6387",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-48795",
            "CVE-2023-51384",
            "CVE-2025-32728",
          ],
        },
      ],
    },
    {
      ip: "192.168.1.108",
      services: [
        {
          port: "22/tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1 Debian 2+deb12u6",
          cves: [
            "CVE-2023-38408",
            "CVE-2023-28531",
            "CVE-2024-6387",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-48795",
            "CVE-2023-51384",
            "CVE-2025-32728",
          ],
        },
      ],
    },
    {
      ip: "192.168.1.254",
      services: [
        {
          port: "53/tcp",
          service: "domain",
          product: "Unbound",
          version: "1.22.0",
          cves: [],
        },
        {
          port: "80/tcp",
          service: "http",
          product: "OPNsense",
          version: "",
          cves: [],
        },
      ],
    },
    {
      ip: "192.168.1.99",
      services: [
        {
          port: "22/tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1 Debian 2+deb12u6",
          cves: [
            "CVE-2023-38408",
            "CVE-2023-28531",
            "CVE-2024-6387",
            "CVE-2025-26465",
            "CVE-2023-51385",
            "CVE-2023-48795",
            "CVE-2023-51384",
            "CVE-2025-32728",
          ],
        },
      ],
    },
  ],
}

// Rapports simulés
const reportsData = [
  {
    id: "scan_20250626-113641",
    name: "Scan Réseau - 26/06/2025",
    date: "2025-06-26T11:36:41Z",
    type: "JSON",
    size: "15.2 KB",
    hosts: 7,
    services: 23,
    cves: 8,
    status: "completed",
  },
  {
    id: "scan_20250625-143022",
    name: "Scan Réseau - 25/06/2025",
    date: "2025-06-25T14:30:22Z",
    type: "PDF",
    size: "2.1 MB",
    hosts: 5,
    services: 18,
    cves: 3,
    status: "completed",
  },
  {
    id: "scan_20250624-091545",
    name: "Scan Réseau - 24/06/2025",
    date: "2025-06-24T09:15:45Z",
    type: "HTML",
    size: "856 KB",
    hosts: 6,
    services: 21,
    cves: 12,
    status: "completed",
  },
]

// Variables globales
let isScanning = false
let scanProgress = 0
let scanInterval
let filteredHosts = [...scanData.hosts]

// Navigation
function showPage(pageId) {
  // Masquer toutes les pages
  document.querySelectorAll(".page").forEach((page) => {
    page.classList.remove("active")
  })

  // Masquer tous les liens actifs
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.remove("active")
  })

  // Afficher la page sélectionnée
  document.getElementById(pageId).classList.add("active")

  // Activer le lien correspondant
  document.querySelector(`[data-page="${pageId}"]`).classList.add("active")

  // Initialiser la page si nécessaire
  if (pageId === "results") {
    initResultsPage()
  } else if (pageId === "reports") {
    initReportsPage()
  }
}

// Scanner
function startScan() {
  if (isScanning) return

  isScanning = true
  scanProgress = 0

  const scanBtn = document.getElementById("scanBtn")
  const progressDiv = document.getElementById("scanProgress")
  const resultsDiv = document.getElementById("scanResults")
  const console = document.getElementById("console")

  // Mettre à jour l'interface
  scanBtn.innerHTML = '<i class="fas fa-square"></i> Arrêter le Scan'
  scanBtn.onclick = stopScan
  progressDiv.style.display = "block"
  resultsDiv.style.display = "none"

  // Vider la console et ajouter le message de démarrage
  console.textContent = ""
  addConsoleMessage("Démarrage du scan sur " + document.getElementById("target").value)
  addConsoleMessage("Découverte des hôtes actifs...")

  // Simuler le scan avec progression
  scanInterval = setInterval(() => {
    scanProgress += 10
    updateScanProgress()

    if (scanProgress >= 100) {
      completeScan()
    }
  }, 500)
}

function stopScan() {
  if (!isScanning) return

  isScanning = false
  clearInterval(scanInterval)

  const scanBtn = document.getElementById("scanBtn")
  const progressDiv = document.getElementById("scanProgress")

  scanBtn.innerHTML = '<i class="fas fa-play"></i> Démarrer le Scan'
  scanBtn.onclick = startScan
  progressDiv.style.display = "none"

  addConsoleMessage("Scan arrêté par l'utilisateur")
}

function updateScanProgress() {
  const progressFill = document.getElementById("progressFill")
  const progressText = document.getElementById("progressText")
  const progressStep = document.getElementById("progressStep")

  progressFill.style.width = scanProgress + "%"
  progressText.textContent = scanProgress + "%"

  // Mettre à jour l'étape
  if (scanProgress < 30) {
    progressStep.textContent = "Découverte des hôtes"
    if (scanProgress === 20) {
      addConsoleMessage("7 hôtes détectés")
    }
  } else if (scanProgress < 70) {
    progressStep.textContent = "Scan des ports"
    if (scanProgress === 40) {
      addConsoleMessage("Scan des ports en cours...")
    }
  } else if (scanProgress < 90) {
    progressStep.textContent = "Détection des services"
    if (scanProgress === 80) {
      addConsoleMessage("Détection des services...")
    }
  } else {
    progressStep.textContent = "Recherche de vulnérabilités"
    if (scanProgress === 90) {
      addConsoleMessage("Recherche de vulnérabilités CVE...")
    }
  }
}

function completeScan() {
  clearInterval(scanInterval)
  isScanning = false

  const scanBtn = document.getElementById("scanBtn")
  const progressDiv = document.getElementById("scanProgress")
  const resultsDiv = document.getElementById("scanResults")

  // Mettre à jour l'interface
  scanBtn.innerHTML = '<i class="fas fa-play"></i> Démarrer le Scan'
  scanBtn.onclick = startScan
  progressDiv.style.display = "none"
  resultsDiv.style.display = "grid"

  // Afficher les résultats
  const totalServices = scanData.hosts.reduce((acc, host) => acc + host.services.length, 0)
  const totalCVEs = scanData.hosts.reduce(
    (acc, host) => acc + host.services.reduce((serviceAcc, service) => serviceAcc + service.cves.length, 0),
    0,
  )

  document.getElementById("resultHosts").textContent = scanData.hosts.length
  document.getElementById("resultServices").textContent = totalServices
  document.getElementById("resultCVEs").textContent = totalCVEs
  document.getElementById("resultDuration").textContent = "45s"

  // Messages de fin
  addConsoleMessage("Scan terminé avec succès")
  addConsoleMessage(`Résultats: ${scanData.hosts.length} hôtes, ${totalServices} services, ${totalCVEs} CVE`)
  addConsoleMessage("Durée totale: 45s")
  addConsoleMessage("Rapport disponible dans l'onglet Résultats")

  // Mettre à jour les stats du dashboard
  updateDashboardStats()
}

function addConsoleMessage(message) {
  const console = document.getElementById("console")
  const timestamp = new Date().toLocaleTimeString()
  const newMessage = `[${timestamp}] ${message}\n`
  console.textContent += newMessage
  console.scrollTop = console.scrollHeight
}

// Résultats
function initResultsPage() {
  displayHosts(filteredHosts)
}

function displayHosts(hosts) {
  const hostsList = document.getElementById("hostsList")
  hostsList.innerHTML = ""

  hosts.forEach((host) => {
    const hostCard = createHostCard(host)
    hostsList.appendChild(hostCard)
  })
}

function createHostCard(host) {
  const card = document.createElement("div")
  card.className = "host-card"

  const servicesTable = host.services
    .map((service) => {
      const cveBadges = service.cves
        .map((cve) => {
          const severity = getCVESeverity(cve)
          return `<span class="cve-badge ${severity}" onclick="openCVE('${cve}')">${cve}</span>`
        })
        .join("")

      return `
            <tr>
                <td style="font-family: monospace;">${service.port}</td>
                <td>${service.service || "-"}</td>
                <td>${service.product || "-"}</td>
                <td>${service.version || "-"}</td>
                <td>
                    <div class="cve-badges">
                        ${cveBadges || '<span style="color: #64748b; font-size: 12px;">Aucune</span>'}
                    </div>
                </td>
            </tr>
        `
    })
    .join("")

  card.innerHTML = `
        <div class="host-header">
            <div class="host-title">
                <i class="fas fa-network-wired"></i>
                ${host.ip}
            </div>
            <span class="badge info">${host.services.length} service${host.services.length > 1 ? "s" : ""}</span>
        </div>
        <div class="card-content">
            <table class="service-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Produit</th>
                        <th>Version</th>
                        <th>CVE</th>
                    </tr>
                </thead>
                <tbody>
                    ${servicesTable}
                </tbody>
            </table>
        </div>
    `

  return card
}

function getCVESeverity(cveId) {
  // Simulation de la sévérité basée sur l'ID
  if (cveId.includes("2024") || cveId.includes("2025")) return "high"
  if (cveId.includes("2023")) return "medium"
  return "low"
}

function openCVE(cveId) {
  window.open(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`, "_blank")
}

function filterResults() {
  const searchTerm = document.getElementById("searchInput").value.toLowerCase()

  filteredHosts = scanData.hosts.filter((host) => {
    return (
      host.ip.includes(searchTerm) ||
      host.services.some(
        (service) =>
          (service.service && service.service.toLowerCase().includes(searchTerm)) ||
          (service.product && service.product.toLowerCase().includes(searchTerm)),
      )
    )
  })

  displayHosts(filteredHosts)
}

// Rapports
function initReportsPage() {
  displayReports()
}

function displayReports() {
  const tbody = document.getElementById("reportsTableBody")
  tbody.innerHTML = ""

  reportsData.forEach((report) => {
    const row = document.createElement("tr")
    row.innerHTML = `
            <td><strong>${report.name}</strong></td>
            <td>${formatDate(report.date)}</td>
            <td><span class="badge ${getTypeBadgeClass(report.type)}">${report.type}</span></td>
            <td>${report.size}</td>
            <td>
                <div style="font-size: 12px;">
                    <div>${report.hosts} hôtes</div>
                    <div style="color: #64748b;">${report.services} services, ${report.cves} CVE</div>
                </div>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-secondary btn-sm btn-icon" onclick="viewReport('${report.id}')" title="Voir">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-secondary btn-sm btn-icon" onclick="downloadReport('${report.id}')" title="Télécharger">
                        <i class="fas fa-download"></i>
                    </button>
                </div>
            </td>
        `
    tbody.appendChild(row)
  })
}

function formatDate(dateString) {
  const date = new Date(dateString)
  return date.toLocaleDateString("fr-FR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

function getTypeBadgeClass(type) {
  switch (type) {
    case "PDF":
      return "danger"
    case "HTML":
      return "info"
    case "JSON":
      return "success"
    default:
      return "info"
  }
}

function generateReport(format) {
  const statusDiv = document.getElementById("generateStatus")
  statusDiv.style.display = "flex"

  // Simuler la génération
  setTimeout(() => {
    statusDiv.style.display = "none"
    alert(`Rapport ${format.toUpperCase()} généré avec succès !`)

    // Ajouter le nouveau rapport à la liste
    const newReport = {
      id: `scan_${Date.now()}`,
      name: `Scan Réseau - ${new Date().toLocaleDateString("fr-FR")}`,
      date: new Date().toISOString(),
      type: format.toUpperCase(),
      size: format === "pdf" ? "2.3 MB" : format === "html" ? "890 KB" : "16.1 KB",
      hosts: scanData.hosts.length,
      services: scanData.hosts.reduce((acc, host) => acc + host.services.length, 0),
      cves: scanData.hosts.reduce(
        (acc, host) => acc + host.services.reduce((serviceAcc, service) => serviceAcc + service.cves.length, 0),
        0,
      ),
      status: "completed",
    }

    reportsData.unshift(newReport)
    displayReports()
  }, 2000)
}

function viewReport(reportId) {
  alert(`Ouverture du rapport ${reportId}`)
}

function downloadReport(reportId) {
  alert(`Téléchargement du rapport ${reportId}`)
}

// Mise à jour des stats du dashboard
function updateDashboardStats() {
  const totalServices = scanData.hosts.reduce((acc, host) => acc + host.services.length, 0)
  const totalCVEs = scanData.hosts.reduce(
    (acc, host) => acc + host.services.reduce((serviceAcc, service) => serviceAcc + service.cves.length, 0),
    0,
  )

  document.getElementById("active-hosts").textContent = scanData.hosts.length
  document.getElementById("total-services").textContent = totalServices
  document.getElementById("critical-cves").textContent = totalCVEs
  document.getElementById("last-scan").textContent = new Date().toLocaleDateString("fr-FR")
}

// Initialisation
document.addEventListener("DOMContentLoaded", () => {
  // Gestionnaires d'événements pour la navigation
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault()
      const pageId = this.getAttribute("data-page")
      showPage(pageId)
    })
  })

  // Initialiser la page dashboard
  showPage("dashboard")
  updateDashboardStats()

  // Initialiser les données des résultats
  filteredHosts = [...scanData.hosts]
})

"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Shield, Network, AlertTriangle, Search, ExternalLink, Download } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

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
  ],
}

export default function ResultsPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [selectedHost, setSelectedHost] = useState<string | null>(null)

  const filteredHosts = scanData.hosts.filter(
    (host) =>
      host.ip.includes(searchTerm) ||
      host.services.some(
        (service) => service.service?.includes(searchTerm.toLowerCase()) || service.product?.includes(searchTerm),
      ),
  )

  const totalServices = scanData.hosts.reduce((acc, host) => acc + host.services.length, 0)
  const totalCVEs = scanData.hosts.reduce(
    (acc, host) => acc + host.services.reduce((serviceAcc, service) => serviceAcc + service.cves.length, 0),
    0,
  )

  const getCVESeverity = (cveId: string) => {
    // Simulation de la sévérité basée sur l'ID
    if (cveId.includes("2024") || cveId.includes("2025")) return "high"
    if (cveId.includes("2023")) return "medium"
    return "low"
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">NovaSentinel - Résultats</h1>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline">
                <Download className="mr-2 h-4 w-4" />
                Exporter JSON
              </Button>
              <Button variant="outline" onClick={() => window.history.back()}>
                Retour
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Informations Réseau */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Network className="mr-2 h-5 w-5" />
              Informations Réseau
            </CardTitle>
            <CardDescription>Scan effectué le {new Date(scanData.timestamp * 1000).toLocaleString()}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <p className="text-sm font-medium text-gray-500">Adresse IP</p>
                <p className="text-lg font-semibold">{scanData.network.ip}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">Interface</p>
                <p className="text-lg font-semibold">{scanData.network.interface}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">Passerelle</p>
                <p className="text-lg font-semibold">{scanData.network.gateway}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-500">DNS</p>
                <p className="text-lg font-semibold">{scanData.network.dns.join(", ")}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Statistiques */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Hôtes Actifs</CardTitle>
              <Network className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{scanData.network.active_hosts}</div>
              <p className="text-xs text-muted-foreground">Hôtes détectés</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Services</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{totalServices}</div>
              <p className="text-xs text-muted-foreground">Services identifiés</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Vulnérabilités</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{totalCVEs}</div>
              <p className="text-xs text-muted-foreground">CVE détectées</p>
            </CardContent>
          </Card>
        </div>

        {/* Recherche */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Rechercher</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative">
              <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Rechercher par IP, service ou produit..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </CardContent>
        </Card>

        {/* Liste des Hôtes */}
        <div className="space-y-6">
          {filteredHosts.map((host) => (
            <Card key={host.ip}>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center">
                    <Network className="mr-2 h-5 w-5" />
                    {host.ip}
                  </span>
                  <Badge variant="outline">
                    {host.services.length} service{host.services.length > 1 ? "s" : ""}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Port</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Produit</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>CVE</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {host.services.map((service, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{service.port}</TableCell>
                        <TableCell>{service.service || "-"}</TableCell>
                        <TableCell>{service.product || "-"}</TableCell>
                        <TableCell>{service.version || "-"}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {service.cves.length > 0 ? (
                              service.cves.map((cve) => (
                                <Badge
                                  key={cve}
                                  variant={
                                    getCVESeverity(cve) === "high"
                                      ? "destructive"
                                      : getCVESeverity(cve) === "medium"
                                        ? "default"
                                        : "secondary"
                                  }
                                  className="text-xs cursor-pointer"
                                  onClick={() =>
                                    window.open(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`, "_blank")
                                  }
                                >
                                  {cve}
                                  <ExternalLink className="ml-1 h-3 w-3" />
                                </Badge>
                              ))
                            ) : (
                              <span className="text-gray-500 text-sm">Aucune</span>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredHosts.length === 0 && (
          <Card>
            <CardContent className="text-center py-8">
              <p className="text-gray-500">Aucun résultat trouvé pour "{searchTerm}"</p>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  )
}

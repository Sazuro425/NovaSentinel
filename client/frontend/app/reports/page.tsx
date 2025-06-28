"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Shield, FileText, Download, Eye, Calendar, Clock } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

// Données simulées des rapports
const reports = [
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

export default function ReportsPage() {
  const [selectedReport, setSelectedReport] = useState<string | null>(null)
  const [isGenerating, setIsGenerating] = useState(false)

  const generateReport = async (format: "html" | "pdf" | "json") => {
    setIsGenerating(true)
    // Simulation de génération de rapport
    setTimeout(() => {
      setIsGenerating(false)
      alert(`Rapport ${format.toUpperCase()} généré avec succès !`)
    }, 2000)
  }

  const downloadReport = (reportId: string) => {
    // Simulation de téléchargement
    alert(`Téléchargement du rapport ${reportId}`)
  }

  const viewReport = (reportId: string) => {
    // Simulation d'ouverture du rapport
    alert(`Ouverture du rapport ${reportId}`)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">NovaSentinel - Rapports</h1>
            </div>
            <Button variant="outline" onClick={() => window.history.back()}>
              Retour
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Génération de Nouveaux Rapports */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="mr-2 h-5 w-5" />
              Générer un Nouveau Rapport
            </CardTitle>
            <CardDescription>Créez un rapport basé sur le dernier scan effectué</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-4">
              <Button onClick={() => generateReport("html")} disabled={isGenerating} className="flex items-center">
                <FileText className="mr-2 h-4 w-4" />
                Rapport HTML
              </Button>
              <Button
                onClick={() => generateReport("pdf")}
                disabled={isGenerating}
                variant="outline"
                className="flex items-center"
              >
                <FileText className="mr-2 h-4 w-4" />
                Rapport PDF
              </Button>
              <Button
                onClick={() => generateReport("json")}
                disabled={isGenerating}
                variant="outline"
                className="flex items-center"
              >
                <FileText className="mr-2 h-4 w-4" />
                Export JSON
              </Button>
            </div>
            {isGenerating && (
              <div className="mt-4 p-4 bg-blue-50 rounded-lg">
                <p className="text-blue-800 flex items-center">
                  <Clock className="mr-2 h-4 w-4 animate-spin" />
                  Génération du rapport en cours...
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Statistiques des Rapports */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Rapports</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{reports.length}</div>
              <p className="text-xs text-muted-foreground">Rapports générés</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Dernier Scan</CardTitle>
              <Calendar className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-lg font-bold">26/06/2025</div>
              <p className="text-xs text-muted-foreground">11:36:41</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Taille Totale</CardTitle>
              <Download className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">3.0 MB</div>
              <p className="text-xs text-muted-foreground">Espace utilisé</p>
            </CardContent>
          </Card>
        </div>

        {/* Liste des Rapports */}
        <Card>
          <CardHeader>
            <CardTitle>Rapports Disponibles</CardTitle>
            <CardDescription>Historique des rapports générés</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Nom du Rapport</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Taille</TableHead>
                  <TableHead>Résultats</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell className="font-medium">{report.name}</TableCell>
                    <TableCell>
                      {new Date(report.date).toLocaleDateString("fr-FR", {
                        day: "2-digit",
                        month: "2-digit",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          report.type === "PDF" ? "destructive" : report.type === "HTML" ? "default" : "secondary"
                        }
                      >
                        {report.type}
                      </Badge>
                    </TableCell>
                    <TableCell>{report.size}</TableCell>
                    <TableCell>
                      <div className="text-sm">
                        <div>{report.hosts} hôtes</div>
                        <div className="text-gray-500">
                          {report.services} services, {report.cves} CVE
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-green-600">
                        Terminé
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex space-x-2">
                        <Button size="sm" variant="outline" onClick={() => viewReport(report.id)}>
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => downloadReport(report.id)}>
                          <Download className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Aperçu du Rapport Sélectionné */}
        {selectedReport && (
          <Card className="mt-8">
            <CardHeader>
              <CardTitle>Aperçu du Rapport</CardTitle>
              <CardDescription>Prévisualisation du rapport sélectionné</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-gray-600">Aperçu du rapport {selectedReport} sera affiché ici...</p>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  )
}

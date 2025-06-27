import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Shield, Network, AlertTriangle, FileText, Play, Eye } from "lucide-react"
import Link from "next/link"

export default function HomePage() {
  // Données simulées basées sur le scan existant
  const stats = {
    activeHosts: 7,
    totalServices: 23,
    criticalCVEs: 8,
    lastScan: "26/06/2025 11:36",
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">NovaSentinel</h1>
            </div>
            <nav className="flex space-x-4">
              <Link href="/scanner" className="text-gray-600 hover:text-gray-900">
                Scanner
              </Link>
              <Link href="/results" className="text-gray-600 hover:text-gray-900">
                Résultats
              </Link>
              <Link href="/reports" className="text-gray-600 hover:text-gray-900">
                Rapports
              </Link>
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-gray-900 mb-4">Scanner de Sécurité Réseau</h2>
          <p className="text-xl text-gray-600 mb-8">
            Analysez votre réseau, détectez les vulnérabilités et générez des rapports complets
          </p>
          <div className="flex justify-center space-x-4">
            <Link href="/scanner">
              <Button size="lg" className="bg-blue-600 hover:bg-blue-700">
                <Play className="mr-2 h-5 w-5" />
                Nouveau Scan
              </Button>
            </Link>
            <Link href="/results">
              <Button variant="outline" size="lg">
                <Eye className="mr-2 h-5 w-5" />
                Voir les Résultats
              </Button>
            </Link>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Hôtes Actifs</CardTitle>
              <Network className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{stats.activeHosts}</div>
              <p className="text-xs text-muted-foreground">Détectés sur le réseau</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Services</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{stats.totalServices}</div>
              <p className="text-xs text-muted-foreground">Services identifiés</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">CVE Critiques</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{stats.criticalCVEs}</div>
              <p className="text-xs text-muted-foreground">Vulnérabilités trouvées</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Dernier Scan</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-sm font-bold">{stats.lastScan}</div>
              <p className="text-xs text-muted-foreground">Scan terminé</p>
            </CardContent>
          </Card>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <Link href="/scanner">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Play className="mr-2 h-5 w-5 text-blue-600" />
                  Lancer un Scan
                </CardTitle>
                <CardDescription>Démarrer une nouvelle analyse du réseau</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600">
                  Scannez votre réseau pour détecter les hôtes actifs, services et vulnérabilités
                </p>
              </CardContent>
            </Link>
          </Card>

          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <Link href="/results">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Eye className="mr-2 h-5 w-5 text-green-600" />
                  Voir les Résultats
                </CardTitle>
                <CardDescription>Consulter les derniers résultats de scan</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600">
                  Analysez les hôtes détectés, services et vulnérabilités identifiées
                </p>
              </CardContent>
            </Link>
          </Card>

          <Card className="hover:shadow-lg transition-shadow cursor-pointer">
            <Link href="/reports">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <FileText className="mr-2 h-5 w-5 text-purple-600" />
                  Générer un Rapport
                </CardTitle>
                <CardDescription>Créer des rapports PDF ou HTML</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600">Exportez vos résultats sous forme de rapports professionnels</p>
              </CardContent>
            </Link>
          </Card>
        </div>

        {/* Recent Activity */}
        <Card className="mt-12">
          <CardHeader>
            <CardTitle>Activité Récente</CardTitle>
            <CardDescription>Dernières actions effectuées</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <div className="flex-1">
                  <p className="text-sm font-medium">Scan réseau terminé</p>
                  <p className="text-xs text-gray-500">7 hôtes détectés - il y a 2 heures</p>
                </div>
                <Badge variant="secondary">Succès</Badge>
              </div>
              <div className="flex items-center space-x-4">
                <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                <div className="flex-1">
                  <p className="text-sm font-medium">8 CVE critiques détectées</p>
                  <p className="text-xs text-gray-500">OpenSSH vulnérabilités - il y a 2 heures</p>
                </div>
                <Badge variant="destructive">Critique</Badge>
              </div>
              <div className="flex items-center space-x-4">
                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                <div className="flex-1">
                  <p className="text-sm font-medium">Rapport PDF généré</p>
                  <p className="text-xs text-gray-500">network_report.pdf - il y a 3 heures</p>
                </div>
                <Badge variant="outline">Info</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  )
}

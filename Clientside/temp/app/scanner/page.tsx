"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { Play, Square, Settings, Network, Shield, AlertTriangle } from "lucide-react"
import { Textarea } from "@/components/ui/textarea"

export default function ScannerPage() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanResults, setScanResults] = useState<any>(null)
  const [scanConfig, setScanConfig] = useState({
    target: "192.168.1.0/24",
    ports: "1-1000",
    enableCVE: true,
    enableService: true,
  })

  const startScan = async () => {
    setIsScanning(true)
    setScanProgress(0)

    // Simulation du scan avec progression
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsScanning(false)
          // Charger les résultats simulés
          setScanResults({
            hosts: 7,
            services: 23,
            cves: 8,
            duration: "45s",
          })
          return 100
        }
        return prev + 10
      })
    }, 500)
  }

  const stopScan = () => {
    setIsScanning(false)
    setScanProgress(0)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">NovaSentinel - Scanner</h1>
            </div>
            <Button variant="outline" onClick={() => window.history.back()}>
              Retour
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Configuration du Scan */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Settings className="mr-2 h-5 w-5" />
                  Configuration
                </CardTitle>
                <CardDescription>Paramètres du scan réseau</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="target">Cible (IP/Réseau)</Label>
                  <Input
                    id="target"
                    value={scanConfig.target}
                    onChange={(e) => setScanConfig({ ...scanConfig, target: e.target.value })}
                    placeholder="192.168.1.0/24"
                    disabled={isScanning}
                  />
                </div>

                <div>
                  <Label htmlFor="ports">Ports à scanner</Label>
                  <Input
                    id="ports"
                    value={scanConfig.ports}
                    onChange={(e) => setScanConfig({ ...scanConfig, ports: e.target.value })}
                    placeholder="1-1000"
                    disabled={isScanning}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="enableService"
                      checked={scanConfig.enableService}
                      onChange={(e) => setScanConfig({ ...scanConfig, enableService: e.target.checked })}
                      disabled={isScanning}
                    />
                    <Label htmlFor="enableService">Détection de services</Label>
                  </div>

                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="enableCVE"
                      checked={scanConfig.enableCVE}
                      onChange={(e) => setScanConfig({ ...scanConfig, enableCVE: e.target.checked })}
                      disabled={isScanning}
                    />
                    <Label htmlFor="enableCVE">Recherche de CVE</Label>
                  </div>
                </div>

                <div className="pt-4">
                  {!isScanning ? (
                    <Button onClick={startScan} className="w-full" size="lg">
                      <Play className="mr-2 h-5 w-5" />
                      Démarrer le Scan
                    </Button>
                  ) : (
                    <Button onClick={stopScan} variant="destructive" className="w-full" size="lg">
                      <Square className="mr-2 h-5 w-5" />
                      Arrêter le Scan
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Résultats et Progression */}
          <div className="lg:col-span-2 space-y-6">
            {/* Progression du Scan */}
            {isScanning && (
              <Card>
                <CardHeader>
                  <CardTitle>Scan en cours...</CardTitle>
                  <CardDescription>Analyse du réseau {scanConfig.target}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <Progress value={scanProgress} className="w-full" />
                    <div className="flex justify-between text-sm text-gray-600">
                      <span>Progression: {scanProgress}%</span>
                      <span>
                        Étape:{" "}
                        {scanProgress < 30
                          ? "Découverte des hôtes"
                          : scanProgress < 70
                            ? "Scan des ports"
                            : scanProgress < 90
                              ? "Détection des services"
                              : "Recherche de vulnérabilités"}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Résultats du Scan */}
            {scanResults && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center">
                      <Network className="mr-2 h-4 w-4 text-green-600" />
                      Hôtes
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-green-600">{scanResults.hosts}</div>
                    <p className="text-xs text-muted-foreground">Hôtes actifs</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center">
                      <Shield className="mr-2 h-4 w-4 text-blue-600" />
                      Services
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-blue-600">{scanResults.services}</div>
                    <p className="text-xs text-muted-foreground">Services détectés</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center">
                      <AlertTriangle className="mr-2 h-4 w-4 text-red-600" />
                      CVE
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-red-600">{scanResults.cves}</div>
                    <p className="text-xs text-muted-foreground">Vulnérabilités</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Durée</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{scanResults.duration}</div>
                    <p className="text-xs text-muted-foreground">Temps écoulé</p>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Console de Log */}
            <Card>
              <CardHeader>
                <CardTitle>Console de Log</CardTitle>
                <CardDescription>Sortie en temps réel du scanner</CardDescription>
              </CardHeader>
              <CardContent>
                <Textarea
                  className="font-mono text-sm h-64 bg-black text-green-400"
                  value={
                    isScanning
                      ? `[${new Date().toLocaleTimeString()}] Démarrage du scan sur ${scanConfig.target}
[${new Date().toLocaleTimeString()}] Découverte des hôtes actifs...
[${new Date().toLocaleTimeString()}] 7 hôtes détectés
[${new Date().toLocaleTimeString()}] Scan des ports en cours...
[${new Date().toLocaleTimeString()}] Détection des services...
[${new Date().toLocaleTimeString()}] Recherche de vulnérabilités CVE...`
                      : scanResults
                        ? `[${new Date().toLocaleTimeString()}] Scan terminé avec succès
[${new Date().toLocaleTimeString()}] Résultats: ${scanResults.hosts} hôtes, ${scanResults.services} services, ${scanResults.cves} CVE
[${new Date().toLocaleTimeString()}] Durée totale: ${scanResults.duration}
[${new Date().toLocaleTimeString()}] Rapport disponible dans l'onglet Résultats`
                        : "En attente du démarrage du scan..."
                  }
                  readOnly
                />
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  )
}

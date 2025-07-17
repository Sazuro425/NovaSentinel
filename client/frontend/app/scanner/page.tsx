"use client"

import { useState } from "react"
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Network, Shield, AlertTriangle } from "lucide-react"
import { Textarea } from "@/components/ui/textarea"

export default function ScannerPage() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanResults, setScanResults] = useState<any>(null)

  /* simulation rapide — garde ton vrai startScan ici */
  const startScan = () => {
    setIsScanning(true)
    setScanProgress(0)
    const i = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 100) {
          clearInterval(i)
          setIsScanning(false)
          setScanResults({ hosts: 7, services: 23, cves: 8, duration: "45 s" })
          return 100
        }
        return p + 10
      })
    }, 500)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* ───── Header ───── */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <h1 className="text-2xl font-bold text-gray-900">NovaSentinel – Scanner</h1>
          </div>
          <Button onClick={startScan} disabled={isScanning}>
            {isScanning ? "Scan en cours…" : "Démarrer le scan"}
          </Button>
        </div>
      </header>

      {/* ───── Contenu principal ───── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Progression */}
          {isScanning && (
            <Card>
              <CardHeader>
                <CardTitle>Scan en cours…</CardTitle>
                <CardDescription>Analyse du réseau</CardDescription>
              </CardHeader>
              <CardContent>
                <Progress value={scanProgress} className="w-full" />
                <p className="text-sm text-right mt-2">{scanProgress}%</p>
              </CardContent>
            </Card>
          )}

          {/* Résultats */}
          {scanResults && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 lg:col-span-2">
              {[
                { label: "Hôtes", value: scanResults.hosts, icon: Network, color: "green" },
                { label: "Services", value: scanResults.services, icon: Shield, color: "blue" },
                { label: "CVE", value: scanResults.cves, icon: AlertTriangle, color: "red" },
              ].map(({ label, value, icon: Icon, color }) => (
                <Card key={label}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center">
                      <Icon className={`mr-2 h-4 w-4 text-${color}-600`} />
                      {label}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className={`text-2xl font-bold text-${color}-600`}>{value}</div>
                  </CardContent>
                </Card>
              ))}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Durée</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{scanResults.duration}</div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Console */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Console de log</CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                readOnly
                className="font-mono text-sm h-64 bg-black text-green-400"
                value={
                  isScanning
                    ? "[…] Scan en cours…"
                    : scanResults
                      ? "[…] Scan terminé."
                      : "En attente du démarrage du scan…"
                }
              />
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}

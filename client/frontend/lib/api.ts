// lib/api.ts
export interface ScanStats {
  activeHosts: number;
  totalServices: number;
  criticalCVEs: number;
  lastScan: string;
}

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function launchScan(): Promise<ScanStats> {
  const res = await fetch(`${BASE}/scan`, { method: "POST" });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${text}`);
  }
  return res.json();
}
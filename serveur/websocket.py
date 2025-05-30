#!/usr/bin/env python3
import asyncio
import websockets
import json

async def handler(websocket):
    print("🔌 Nouveau client connecté")
    async for message in websocket:
        try:
            data = json.loads(message)
            print("✅ Données reçues (dict) :")
            print(f"  - Interface   : {data.get('interface')}")
            print(f"  - IP locale   : {data.get('ip')}")
            print(f"  - Passerelle  : {data.get('gateway')}")
            print(f"  - DHCP server : {data.get('dhcp')}")
            print(f"  - DNS         : {', '.join(data.get('dns', []))}")
            print(f"  - Hôtes actifs: {', '.join(data.get('hosts_up', []))}")
        except json.JSONDecodeError:
            print("❌ Erreur : données reçues non valides (JSON attendu)")
        except Exception as e:
            print(f"⚠️ Erreur inattendue : {e}")

async def main():
    print("🚀 Lancement du serveur WebSocket...")
    async with websockets.serve(handler, "localhost", 8000):
        print("✅ Serveur en écoute sur ws://localhost:8000")
        await asyncio.Future()  # Boucle infinie

if __name__ == "__main__":
    asyncio.run(main())

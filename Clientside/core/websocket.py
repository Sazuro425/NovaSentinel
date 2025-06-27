import mydotenv   # Ensure .env is loaded
import websockets

server = mydotenv.get_env("SERVER")
port = mydotenv.get_env("PORT", "8765")  # Default port if not set

def test_connection():
    """Teste la connexion au serveur WebSocket."""
    uri = f"ws://{server}:{port}"
    try:
        async with websockets.connect(uri) as websocket:
            print(f"Connexion réussie à {uri}")
            return True
    except Exception as e:
        print(f"Échec de la connexion à {uri}: {e}")
        return False
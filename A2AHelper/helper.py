from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import threading
import urllib3

# Import HelperAgent class
from routes.helper_agent import HelperAgent

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get port from .env
PORT = int(os.getenv("PORT", 5001))
AGENT_ID = os.getenv("AGENT_ID", "helper_1")
CONTROLLER_ADDRESS = os.getenv("CONTROLLER_ADDRESS", "https://127.0.0.1:5000")

# Initialize agent
agent = HelperAgent()

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the A2A Helper Agent"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/message', methods=['POST'])
def receive_message():
    data = request.json
    print(f"\n[RECEIVED] {data}")
    return jsonify({"status": "received"}), 200


def run_flask():
        app.run(
        host='0.0.0.0',
        port=PORT,
        debug=False,
        use_reloader=False,
        ssl_context=("cert.pem", "key.pem")  
    )


if __name__ == "__main__":
    # Start Flask server in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    print(f"Helper Agent ({AGENT_ID}) running on port {PORT}")
    print("Type 'help' for commands\n")
    
    # Interactive CLI loop
    while True:
        cmd = input(f"{AGENT_ID}> ").strip().lower()
        
        if cmd == "help":
            print("Commands: help | status | trust | register | cards | exit")
        elif cmd == "status":
            print(f"Agent: {AGENT_ID}, Port: {PORT}, Status: Active")
            trust_status = "✓ Established" if agent.controller_public_key else "✗ Not established"
            print(f"Trust Anchor: {trust_status}")
        elif cmd == "trust":
            print(f"Establishing trust with controller at {CONTROLLER_ADDRESS}...")
            success, message = agent.download_controller_public_key(CONTROLLER_ADDRESS)
            
            if success:
                print(f"✓ {message}")
            else:
                print(f"✗ {message}")
        elif cmd == "register":
            print(f"Registering agent with controller at {CONTROLLER_ADDRESS}...")
            success, result = agent.register_with_controller(CONTROLLER_ADDRESS)
            
            if success:
                print("✓ Registration successful!")
                print(f"Certificate received from controller")
                print(f"Agent ID: {result['agent_card']['agent_id']}")
                print(f"Controller signature: {result['controller_signature'][:50]}...")
            else:
                print(f"✗ Registration failed: {result}")
        elif cmd == "cards":
            success, result = agent.get_all_agent_cards(CONTROLLER_ADDRESS)
            if not success:
                print(f"✗ Failed to retrieve cards: {result}")
        elif cmd == "exit":
            print("Shutting down...")
            break
        else:
            print(f"Unknown command: {cmd}")
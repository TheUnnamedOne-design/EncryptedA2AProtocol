from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import threading

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get port from .env
PORT = int(os.getenv("PORT", 5002))
AGENT_ID = os.getenv("AGENT_ID", "traveller_1")

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the A2A Traveller Agent"

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
    
    print(f"Traveller Agent ({AGENT_ID}) running on port {PORT}")
    print("Type 'help' for commands\n")
    
    # Interactive CLI loop
    while True:
        cmd = input(f"{AGENT_ID}> ").strip().lower()
        
        if cmd == "help":
            print("Commands: help | status | exit")
        elif cmd == "status":
            print(f"Agent: {AGENT_ID}, Port: {PORT}, Status: Active")
        elif cmd == "exit":
            print("Shutting down...")
            break
        else:
            print(f"Unknown command: {cmd}")
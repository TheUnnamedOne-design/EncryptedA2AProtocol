from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv


from routes.health import health_bp

load_dotenv()

app=Flask(__name__)
CORS(app)

app.register_blueprint(health_bp)

@app.route('/',methods=['GET'])
def home():
    return "Welcome to the A2A Protocol Server"

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"Starting server at http://localhost:{port}")
    app.run(host='0.0.0.0',port=port,debug=True)
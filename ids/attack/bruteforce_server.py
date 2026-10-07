#from pc to pc



from flask import Flask, request, jsonify

app = Flask(__name__)

HOST = "0.0.0.0"
PORT = 8080

# Test-only credentials
VALID_USERNAME = "admin"
VALID_PASSWORD = "test123"

attempts = 0


@app.route("/", methods=["GET"])
def home():
    return "AI-NIDS Brute Force Test Server"


@app.route("/login", methods=["POST"])
def login():
    global attempts

    attempts += 1

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if username == VALID_USERNAME and password == VALID_PASSWORD:
        return jsonify({
            "success": True,
            "message": "Login successful"
        })

    return jsonify({
        "success": False,
        "message": "Invalid username or password",
        "attempt": attempts
    }), 401


if __name__ == "__main__":
    print("======================================")
    print(" AI-NIDS Brute Force Test Server")
    print("======================================")
    print(f"Listening on: http://0.0.0.0:{PORT}")
    print("Test endpoint: /login")
    print("Press CTRL+C to stop.")
    print()

    app.run(host=HOST, port=PORT, threaded=True)
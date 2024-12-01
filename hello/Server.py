from quart import Quart, request, jsonify
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")
app = Quart(__name__)

@app.before_request
async def log_request():
    logging.info(f"Received request: {request.method} {request.path} from {request.remote_addr}")

@app.route("/", methods=["POST"])
async def chat():
    data = await request.get_json()  # Receive JSON data
    message = data.get("message", "")
    logging.info(f"Payload: {data}")
    response_message = f"Server received: '{message}'"
    return jsonify({"response": response_message}), 200

@app.after_request
async def log_response(response):
    logging.info(f"Response: {response.status_code}")
    return response

if __name__ == "__main__":
    import ssl
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    # Configure SSL for HTTP/2
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    config = Config()
    config.bind = ["127.0.0.1:8443"]
    config.certfile = "cert.pem"
    config.keyfile = "key.pem"
    config.alpn_protocols = ["h2"]

    import asyncio
    asyncio.run(serve(app, config))

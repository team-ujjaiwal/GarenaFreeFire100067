import time
import httpx
import json
import threading
import asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def json_to_proto_sync(json_data: str, proto_message) -> bytes:
    from google.protobuf import json_format
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_type) -> dict:
    from google.protobuf import json_format
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return json.loads(json_format.MessageToJson(instance))

# === JWT Token Generation ===
def generate_jwt_token_sync(uid: str, password: str):
    # Import protobuf modules
    import FreeFire_pb2
    
    # Create account credentials string
    account = f"uid={uid}&password={password}"
    
    # Step 1: Get access token
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    
    # Use synchronous HTTP client
    with httpx.Client() as client:
        resp = client.post(url, data=payload, headers=headers)
        data = resp.json()
        token_val = data.get("access_token", "0")
        open_id = data.get("open_id", "0")
    
    # Step 2: Create JWT token
    body = json.dumps({
        "open_id": open_id, 
        "open_id_type": "4", 
        "login_token": token_val, 
        "orign_platform_type": "4"
    })
    
    proto_bytes = json_to_proto_sync(body, FreeFire_pb2.LoginReq())
    payload_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue", 
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1", 
        'ReleaseVersion': RELEASEVERSION
    }
    
    with httpx.Client() as client:
        resp = client.post(url, data=payload_enc, headers=headers)
        msg = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
        
        # Format response as requested
        response_data = {
            "accountId": msg.get("accountId", ""),
            "lockRegion": msg.get("lockRegion", ""),
            "notiRegion": msg.get("notiRegion", ""),
            "ipRegion": msg.get("ipRegion", ""),
            "agoraEnvironment": msg.get("agoraEnvironment", ""),
            "newActiveRegion": msg.get("newActiveRegion", ""),
            "recommendRegions": msg.get("recommendRegions", []),
            "token": msg.get("token", ""),
            "ttl": msg.get("ttl", 0),
            "serverUrl": msg.get("serverUrl", ""),
            "expireAt": int(time.time()) + msg.get("ttl", 0)
        }
        
        return response_data

# === Flask Routes ===
@app.route('/token', methods=['GET'])
def get_jwt_token():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    if not password:
        return jsonify({"error": "Please provide password."}), 400
    
    try:
        token_data = generate_jwt_token_sync(uid, password)
        return jsonify(token_data), 200
    
    except Exception as e:
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

# === Startup ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
import os
import uuid
import boto3
import requests
import json
from functools import wraps
from jose import jwk, jwt as jose_jwt
from jose.exceptions import JOSEError, ExpiredSignatureError, JWTClaimsError
from jose.utils import base64url_decode
from flask import Flask, render_template, request, jsonify, g
from flask_cors import CORS
from werkzeug.utils import secure_filename
from botocore.exceptions import ClientError

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# --- CONFIGURATION (PASTE YOUR IDs) ---
COGNITO_USER_POOL_ID = 'us-east-1_EqUH81ByT' # <-- PASTE YOUR Pool Id HERE
COGNITO_APP_CLIENT_ID = '5fprntguvdnhloun9jeqat7cfr' # <-- PASTE YOUR App client id HERE
AWS_REGION = 'us-east-1'  # Or your pool's region

S3_BUCKET_NAME = 'spotify-clone-mp3s' # <-- PASTE your S3 bucket name
SONGS_TABLE_NAME = 'orders'     # <-- Your 'orders' table
PLAYLISTS_TABLE_NAME = 'playlists' # <-- Your 'playlists' table
# --- END CONFIGURATION ---


# --- CUSTOM COGNITO AUTH ---
COGNITO_ISSUER = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"

try:
    response = requests.get(JWKS_URL)
    response.raise_for_status()
    COGNITO_JWKS = response.json()["keys"]
    print("[AUTH] Successfully fetched Cognito JWKS.")
except requests.exceptions.RequestException as e:
    print(f"[AUTH ERROR] Failed to fetch JWKS: {e}")
    COGNITO_JWKS = []

def get_key_from_kid(kid):
    key = next((k for k in COGNITO_JWKS if k["kid"] == kid), None)
    if key:
        return jwk.construct(key).to_pem()
    else:
        print(f"[AUTH ERROR] No matching key found for kid: {kid}")
        raise Exception("Public key not found.")

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                print("[AUTH ERROR] Missing Authorization Header")
                return jsonify({"error": "Missing Authorization Header"}), 401
            
            if not auth_header.startswith("Bearer "):
                print("[AUTH ERROR] Invalid Authorization Header")
                return jsonify({"error": "Invalid Authorization Header"}), 401
                
            token = auth_header.split(" ")[1]
            unverified_header = jose_jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            public_key = get_key_from_kid(kid)

            decoded_token = jose_jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=COGNITO_APP_CLIENT_ID,
                issuer=COGNITO_ISSUER
            )
            
            if decoded_token.get("token_use") != "id":
                print("[AUTH ERROR] Token is not an 'id' token")
                return jsonify({"error": "Token is not an 'id' token"}), 401

            g.user_email = decoded_token.get("email") # (FIX) Use 'email' claim from ID token
            if not g.user_email:
                print("[AUTH ERROR] Token valid but 'email' claim missing")
                return jsonify({"error": "Token valid but 'email' claim missing"}), 401
            
            print(f"[AUTH] Success for user: {g.user_email}")

        except ExpiredSignatureError:
            print("[AUTH ERROR] Token has expired")
            return jsonify({"error": "Token has expired"}), 401
        except JWTClaimsError as e:
            print(f"[AUTH ERROR] Invalid claims: {e}")
            return jsonify({"error": f"Invalid claims: {e}"}), 401
        except JOSEError as e:
            print(f"[AUTH ERROR] JOSEError: {e}")
            return jsonify({"error": f"Token is invalid: {e}"}), 401
        except Exception as e:
            print(f"[AUTH ERROR] An unexpected error occurred: {e}")
            return jsonify({"error": "An unexpected error occurred"}), 500
        
        return f(*args, **kwargs)
    return decorated_function
# --- END AUTH CONFIG ---


# --- AWS Setup ---
dynamodb = boto3.resource('dynamodb')
sqs = boto3.client('sqs')
s3 = boto3.client('s3')

songs_table = dynamodb.Table(SONGS_TABLE_NAME)
playlists_table = dynamodb.Table(PLAYLISTS_TABLE_NAME)

SQS_QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/104791707000/order_queue' # (This was your SQS)


# --- Helper Functions ---
def upload_file_to_s3(file, bucket_name, object_name=None, acl="public-read"):
    if object_name is None:
        object_name = secure_filename(file.filename)
    
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            object_name,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )
        s3_url = f"https://{bucket_name}.s3.amazonaws.com/{object_name}"
        return s3_url
    except Exception as e:
        print(f"[S3 ERROR] {e}")
        return None

# --- Routes ---
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/upload", methods=["POST"])
@auth_required
def upload_song():
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401

        if 'mp3_file' not in request.files or 'image_file' not in request.files:
            return jsonify({"error": "Missing mp3_file or image_file"}), 400
            
        mp3_file = request.files['mp3_file']
        image_file = request.files['image_file']
        title = request.form.get("title")
        artist = request.form.get("artist")

        if not title or not artist or mp3_file.filename == '' or image_file.filename == '':
            return jsonify({"error": "Missing title, artist, or files"}), 400

        song_id = str(uuid.uuid4())
        mp3_filename = f"audio/{song_id}.mp3"
        image_filename = f"images/{song_id}.{image_file.filename.split('.')[-1]}"

        mp3_s3_url = upload_file_to_s3(mp3_file, S3_BUCKET_NAME, mp3_filename)
        image_s3_url = upload_file_to_s3(image_file, S3_BUCKET_NAME, image_filename)

        if not mp3_s3_url or not image_s3_url:
            return jsonify({"error": "File upload to S3 failed"}), 500

        song_item = {
            'order_id': song_id,
            'song_id': song_id,
            'title': title,
            'artist': artist,
            's3_url': mp3_s3_url,
            'image_url': image_s3_url,
            'uploaded_by': user_email
        }
        songs_table.put_item(Item=song_item)
        
        try:
            sqs.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=json.dumps({"song_id": song_id, "title": title, "status": "NEW_UPLOAD"})
            )
        except Exception as e:
            print(f"[SQS ERROR] {e}")

        return jsonify(song_item), 201

    except Exception as e:
        print(f"[UPLOAD ERROR] {e}")
        return jsonify({"error": "An internal error occurred"}), 500


@app.route("/api/songs", methods=["GET"])
@auth_required
def get_songs():
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401

        response = songs_table.scan()
        songs = response.get('Items', [])
        return jsonify(songs), 200
    except Exception as e:
        print(f"[GET_SONGS ERROR] {e}")
        return jsonify({"error": "Could not fetch songs"}), 500


@app.route("/api/playlists", methods=["GET"])
@auth_required
def get_playlists():
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401
        
        response = playlists_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('user_id').eq(user_email)
        )
        playlists = response.get('Items', [])
        return jsonify(playlists), 200
    except Exception as e:
        print(f"[GET_PLAYLISTS ERROR] {e}")
        return jsonify({"error": "Could not fetch playlists"}), 500


@app.route("/api/playlists", methods=["POST"])
@auth_required
def create_playlist():
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401

        data = request.get_json()
        playlist_name = data.get('name')
        if not playlist_name:
            return jsonify({"error": "Playlist name is required"}), 400

        playlist_id = str(uuid.uuid4())
        playlist_item = {
            'user_id': user_email,
            'playlist_id': playlist_id,
            'name': playlist_name,
            'song_ids': []
        }
        
        playlists_table.put_item(Item=playlist_item)
        return jsonify(playlist_item), 201
        
    except Exception as e:
        print(f"[CREATE_PLAYLIST ERROR] {e}")
        return jsonify({"error": "Could not create playlist"}), 500


# (NEW) Route to delete an entire playlist
@app.route("/api/playlists/<string:playlist_id>", methods=["DELETE"])
@auth_required
def delete_playlist(playlist_id):
    """
    Deletes an entire playlist.
    """
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401
        
        # DynamoDB delete_item requires the full primary key (Partition + Sort)
        playlists_table.delete_item(
            Key={
                'user_id': user_email,
                'playlist_id': playlist_id
            }
        )
        
        print(f"[PLAYLIST] User {user_email} deleted playlist {playlist_id}")
        return jsonify({"message": "Playlist deleted"}), 200 # Or 204 No Content

    except Exception as e:
        print(f"[DELETE_PLAYLIST ERROR] {e}")
        return jsonify({"error": "Could not delete playlist"}), 500


@app.route("/api/playlists/<string:playlist_id>/add", methods=["POST"])
@auth_required
def add_song_to_playlist(playlist_id):
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401
        
        data = request.get_json()
        song_id = data.get('song_id')
        if not song_id:
            return jsonify({"error": "song_id is required"}), 400
        
        response = playlists_table.update_item(
            Key={
                'user_id': user_email,
                'playlist_id': playlist_id
            },
            UpdateExpression="SET song_ids = list_append(if_not_exists(song_ids, :empty_list), :new_song)",
            ExpressionAttributeValues={
                ':new_song': [song_id],
                ':empty_list': []
            },
            ReturnValues="ALL_NEW"
        )
        
        return jsonify(response.get('Attributes', {})), 200
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationException':
             print(f"[DYNAMODB VALIDATION ERROR] {e}")
             return jsonify({"error": "Validation error, check that song_ids is a list in DynamoDB"}), 400
        print(f"[ADD_SONG_PLAYLIST ERROR] {e}")
        return jsonify({"error": "Could not add song to playlist"}), 500
    except Exception as e:
        print(f"[ADD_SONG_PLAYLIST ERROR] {e}")
        return jsonify({"error": "Could not add song to playlist"}), 500


@app.route("/api/playlists/<string:playlist_id>/remove", methods=["POST"])
@auth_required
def remove_song_from_playlist(playlist_id):
    """
    Removes a song from a playlist.
    This uses a Read-Modify-Write pattern.
    """
    try:
        user_email = g.get('user_email')
        if not user_email:
            return jsonify({"error": "Could not identify user"}), 401
        
        data = request.get_json()
        song_id_to_remove = data.get('song_id')
        if not song_id_to_remove:
            return jsonify({"error": "song_id is required"}), 400
        
        # 1. Read (Get) the playlist
        response = playlists_table.get_item(
            Key={
                'user_id': user_email,
                'playlist_id': playlist_id
            }
        )
        
        playlist = response.get('Item')
        if not playlist:
            return jsonify({"error": "Playlist not found"}), 404
            
        # 2. Modify the song_ids list
        song_ids = playlist.get('song_ids', [])
        
        if song_id_to_remove not in song_ids:
             return jsonify({"error": "Song not found in playlist"}), 404
        
        # Remove all instances of the song_id
        new_song_ids = [sid for sid in song_ids if sid != song_id_to_remove]
        
        # 3. Write (Update) the playlist with the new list
        response = playlists_table.update_item(
            Key={
                'user_id': user_email,
                'playlist_id': playlist_id
            },
            UpdateExpression="SET song_ids = :new_list",
            ExpressionAttributeValues={
                ':new_list': new_song_ids
            },
            ReturnValues="ALL_NEW"
        )
        
        print(f"[PLAYLIST] User {user_email} removed song {song_id_to_remove} from {playlist_id}")
        return jsonify(response.get('Attributes', {})), 200

    except Exception as e:
        print(f"[REMOVE_SONG_PLAYLIST ERROR] {e}")
        return jsonify({"error": "Could not remove song from playlist"}), 500


if __name__ == "__main__":
    # Make sure to install: pip install Flask flask_cors boto3 requests python-jose
    app.run(debug=True, host='0.0.0.0', port=5000)
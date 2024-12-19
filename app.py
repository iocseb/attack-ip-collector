from flask import Flask, render_template, make_response
import json
from user_agents import parse
from collections import Counter
from ipaddress import ip_address
import operator
from datetime import datetime
import csv
from io import StringIO

app = Flask(__name__)

@app.template_filter('datetime')
def format_datetime(timestamp):
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return str(timestamp)

def load_log_entries():
    entries = []
    try:
        with open('access.json', 'r') as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return entries

def analyze_logs(entries):
    stats = {
        'browsers': Counter(),
        'operating_systems': Counter(),
        'ip_addresses': Counter(),
        'status_codes': Counter(),
        'total_requests': len(entries),
        'ipv4_count': 0,
        'ipv6_count': 0,
        'paths': Counter(),
        'hosts': Counter(),
        'wp_admin_attempts': [],
        'wp_admin_ips': Counter()
    }
    
    for entry in entries:
        # Extract request info
        request = entry.get('request', {})
        
        # Parse User-Agent
        user_agent_string = request.get('headers', {}).get('User-Agent', [''])[0]
        if user_agent_string:
            user_agent = parse(user_agent_string)
            stats['browsers'][user_agent.browser.family] += 1
            stats['operating_systems'][user_agent.os.family] += 1
        
        # Count IP addresses
        ip = request.get('remote_ip', '')
        if ip:
            stats['ip_addresses'][ip] += 1
            try:
                if ':' in ip:
                    stats['ipv6_count'] += 1
                else:
                    stats['ipv4_count'] += 1
            except:
                pass
        
        # Count status codes
        stats['status_codes'][entry.get('status', 'unknown')] += 1
        
        # Count paths
        stats['paths'][request.get('uri', '')] += 1
        
        # Count hosts
        stats['hosts'][request.get('host', '')] += 1
        
        # Track wp-admin attempts
        uri = request.get('uri', '')
        if 'wp-admin' in uri.lower():
            wp_attempt = {
                'ip': request.get('remote_ip', ''),
                'path': uri,
                'timestamp': entry.get('ts', ''),
                'user_agent': request.get('headers', {}).get('User-Agent', [''])[0],
                'status': entry.get('status', '')
            }
            stats['wp_admin_attempts'].append(wp_attempt)
            stats['wp_admin_ips'][wp_attempt['ip']] += 1
    
    # Sort wp-admin attempts by timestamp
    stats['wp_admin_attempts'].sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get top attackers (top 5 IPs with most wp-admin attempts)
    stats['top_attackers'] = dict(sorted(stats['wp_admin_ips'].items(),
                                       key=operator.itemgetter(1), reverse=True)[:5])
    
    # Get top entries
    stats['top_browsers'] = dict(sorted(stats['browsers'].items(), 
                                      key=operator.itemgetter(1), reverse=True)[:5])
    stats['top_os'] = dict(sorted(stats['operating_systems'].items(), 
                                 key=operator.itemgetter(1), reverse=True)[:5])
    stats['top_ips'] = dict(sorted(stats['ip_addresses'].items(), 
                                  key=operator.itemgetter(1), reverse=True)[:5])
    stats['top_paths'] = dict(sorted(stats['paths'].items(), 
                                    key=operator.itemgetter(1), reverse=True)[:5])
    stats['top_hosts'] = dict(sorted(stats['hosts'].items(), 
                                    key=operator.itemgetter(1), reverse=True)[:5])
    
    return stats

@app.route('/')
def index():
    entries = load_log_entries()
    stats = analyze_logs(entries)
    return render_template('index.html', stats=stats)

@app.route('/download_attackers_csv')
def download_attackers_csv():
    entries = load_log_entries()
    stats = analyze_logs(entries)
    
    # Create CSV data
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP Address', 'Number of Attempts'])
    
    for ip, count in stats['top_attackers'].items():
        writer.writerow([ip, count])
    
    # Create the response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=wp_attackers.csv'
    
    return response

if __name__ == '__main__':
    app.run(debug=True) 
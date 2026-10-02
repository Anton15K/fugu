import os, subprocess, json, re, sys
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path('/Users/antonkogun/dev/nebius_hack/.env'))
command = ['/tmp/fugu-competitor-snyk/.venv/bin/snyk-agent-scan', 'scan', sys.argv[1], '--json', '--show-analysis-results', '--dangerously-run-mcp-servers', '--no-skills', '--server-timeout', '30']
try:
    cp = subprocess.run(command, text=True, capture_output=True, timeout=210)
    raw = cp.stdout + '\n' + cp.stderr
    token = os.getenv('SNYK_TOKEN')
    if token:
        raw = raw.replace(token, '[REDACTED]')
    raw = re.sub(r'(?i)(authorization[\s\"\x27:]+)([^\n]+)', r'\1[REDACTED]', raw)
    output = {'command': command, 'exit_code': cp.returncode, 'output': raw}
except subprocess.TimeoutExpired:
    output = {'command': command, 'status': 'timeout', 'output': 'Bounded 210-second setup scan did not complete.'}
Path(sys.argv[2]).write_text(json.dumps(output, indent=2))
print(json.dumps({k:v for k,v in output.items() if k not in ['command','output']}))

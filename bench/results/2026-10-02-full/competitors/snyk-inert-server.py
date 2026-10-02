import json, sys
with open('/input/tools.json', encoding='utf8') as f:
    tools = json.load(f)
for line in sys.stdin:
    try:
        req = json.loads(line)
        if 'id' not in req:
            continue
        method = req.get('method')
        if method == 'initialize':
            result = {'protocolVersion': req.get('params', {}).get('protocolVersion', '2025-03-26'), 'capabilities': {'tools': {}, 'prompts': {}, 'resources': {}}, 'serverInfo': {'name': 'benchmark-inert', 'version': '1'}}
        elif method == 'tools/list':
            result = {'tools': tools}
        elif method == 'prompts/list':
            result = {'prompts': []}
        elif method == 'resources/list':
            result = {'resources': []}
        elif method == 'resources/templates/list':
            result = {'resourceTemplates': []}
        elif method == 'ping':
            result = {}
        else:
            print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'error': {'code': -32601, 'message': 'No method'}}), flush=True)
            continue
        print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': result}), flush=True)
    except Exception:
        pass

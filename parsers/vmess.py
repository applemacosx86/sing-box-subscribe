import tool, json, re
from urllib.parse import urlparse, parse_qs

def parse(data):
    info = data[8:]
    if not info or info.isspace():
        return None
    try:
        if info.find('?') > -1:  # Handle non-standard URI format
            server_info = urlparse(info)
            netquery = dict(
                (k, v if len(v) > 1 else v[0])
                for k, v in parse_qs(server_info.query).items()
            )
            try:
                _path = tool.b64Decode(server_info.path).decode('utf-8').split("@")
            except:
                _path = server_info.path.split("@")
            node = {
                'tag': netquery.get('remarks', tool.genName() + '_vmess'),
                'type': 'vmess',
                'server': _path[1].split(":")[0],
                'server_port': int(_path[1].split(":")[1]),
                'uuid': _path[0].split(":")[-1],
                'security': _path[0].split(":")[0] if ':' in _path[0] else 'auto',
                'alter_id': int(netquery.get('alterId', '0')),
                'packet_encoding': 'xudp'
            }
            if (netquery.get('tls') and netquery['tls'] != '') or (netquery.get('security') == 'tls'):
                node['tls'] = {
                    'enabled': True,
                    'insecure': True,
                    'server_name': netquery.get('peer', '')
                }
                if netquery.get('allowInsecure') == '0':
                    node['tls']['insecure'] = False
                if netquery.get('sni'):
                    node['tls']['server_name'] = netquery['sni']
                    node['tls']['utls'] = {
                        'enabled': True,
                        'fingerprint': netquery.get('fp', 'chrome')
                    }
            if (netquery.get('obfs') == 'websocket') or (netquery.get('type') == 'ws'):
                node['transport'] = {
                    'type': 'ws',
                    'path': netquery.get('path', '/').rsplit("?ed=", 1)[0],
                    'headers': {
                        'Host': netquery.get('host', '')
                    }
                }
                obfs_param = netquery.get('obfsParam', '')
                try:
                    obfs_param_json = json.loads(obfs_param)
                    host_from_obfs_param = obfs_param_json.get('Host', '')
                    node['transport']['headers']['Host'] = host_from_obfs_param or netquery.get('host', '')
                except json.JSONDecodeError:
                    pass
            return node
        else:
            proxy_str = tool.b64Decode(info).decode('utf-8')
    except:
        print(info)
        return None
    try:
        item = json.loads(proxy_str)
    except:
        return None
    content = item.get('ps').strip() if item.get('ps') else tool.genName() + '_vmess'
    node = {
        'tag': content,
        'type': 'vmess',
        'server': item.get('add'),
        'server_port': int(item.get('port')),
        'uuid': item.get('id'),
        'security': item.get('scy') if item.get('scy') not in ['http', None] else 'auto',
        'alter_id': int(item.get('aid', '0')),
        'packet_encoding': 'xudp'
    }
    if node['security'] == 'gun':
        node['security'] = 'auto'
    if 'tls' in item and (item['tls'] != '' and item['tls'] != 'none'):
        node['tls'] = {
            'enabled': True,
            'insecure': True,
            'server_name': item.get('host', '') if item.get('net') not in ['h2', 'http'] else ''
        }
        if item.get('verify_cert') == False:
            node['tls']['insecure'] = False
        if item.get('sni'):
            node['tls']['server_name'] = item['sni']
        if item.get('fp'):
            node['tls']['utls'] = {
                'enabled': True,
                'fingerprint': item['fp']
            }
    if item.get('net'):
        if item['net'] in ['h2', 'http']:
            # Only set HTTP transport if path and host are provided
            if item.get('path') and item.get('host'):
                node['transport'] = {
                    'type': 'http',
                    'path': item['path'].rsplit("?")[0] if type(item.get('path')) == str else item['path'][0],
                    'headers': item.get('headers', {}),
                    'host': item.get('host')
                }
                if type(item.get('path')) != str:
                    node['transport']['method'] = 'GET'
        elif item['net'] == 'tcp':
            # Omit transport for TCP (default for vmess)
            pass
        elif item['net'] == 'ws':
            node['transport'] = {
                'type': 'ws',
                'path': item['path'].rsplit("?ed=", 1)[0] if re.search(r'\?ed=(\d+)$', item.get('path', '')) else item.get('path', '/'),
                'headers': {
                    'Host': item.get('host', '')
                }
            }
            if re.search(r'\?ed=(\d+)$', item.get('path', '')):
                node['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                node['transport']['max_early_data'] = int(item['path'].rsplit("?ed=", 1)[1])
        elif item['net'] == 'quic':
            node['transport'] = {
                'type': 'quic'
            }
        elif item['net'] == 'grpc':
            node['transport'] = {
                'type': 'grpc',
                'service_name': item.get('path', '')
            }
    if item.get('protocol') in ['smux', 'yamux', 'h2mux']:
        node['multiplex'] = {
            'enabled': True,
            'protocol': item['protocol']
        }
        if item.get('max_streams'):
            node['multiplex']['max_streams'] = int(item['max_streams'])
        else:
            node['multiplex']['max_connections'] = int(item.get('max_connections', 0))
            node['multiplex']['min_streams'] = int(item.get('min_streams', 0))
        if item.get('padding') == True:
            node['multiplex']['padding'] = True
    return node
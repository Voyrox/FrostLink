from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def any_path(path):
    proto = request.headers.get('X-Forwarded-Proto') or ('https' if request.is_secure else 'http')
    host = request.headers.get('Host', '')

    body = (
        f"Hello World\n"
        f"Protocol: {proto.upper()}\n"
        f"Host: {host}\n"
        f"Method: {request.method}\n"
        f"Path: {request.path}\n"
    )

    resp = make_response(body, 200)
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)

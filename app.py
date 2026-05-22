# run.py
from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST   '])
def run_sqlmap():
    command = request.json.get('command')

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)

    return jsonify({"output": output})

if __name__ == '__main__':
    app.run(debug=True)
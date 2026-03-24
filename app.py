import os
import tempfile
from flask import Flask, request, jsonify, render_template
from magic_reader import identify_file

app = Flask(__name__)

@app.route('/')
def index():
    # Serves templates/index.html
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # request.files holds uploaded files keyed by the form field name.
    # The frontend sends the file under the key 'file'.
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file received'}), 400

    # We must preserve the original filename so identify_file() can read the extension.
    # tempfile.mkdtemp() gives us a fresh directory that we fully control.
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, file.filename)

    # Save the uploaded bytes to disk so identify_file() can open it normally.
    file.save(tmp_path)

    result = identify_file(tmp_path)

    # Clean up — the temp file is no longer needed after analysis.
    os.remove(tmp_path)
    os.rmdir(tmp_dir)

    # Swap the full tmp path for the original filename in the response.
    result['filepath'] = file.filename

    # jsonify() serialises the dict to JSON and sets Content-Type: application/json.
    return jsonify(result)

if __name__ == '__main__':
    # debug=True only applies when running locally with `python3 app.py`.
    # Gunicorn ignores this block entirely — it imports `app` directly.
    app.run(debug=False)

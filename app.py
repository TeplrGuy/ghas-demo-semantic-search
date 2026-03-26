"""
Semantic Search Application using sentence-transformers/all-mpnet-base-v2
A demo app for showcasing GitHub Advanced Security code scanning.
"""
import os
import re
import pickle
import subprocess
import tempfile
import yaml
import sqlite3
import hashlib
from xml.etree import ElementTree as ET
from flask import Flask, request, render_template_string, jsonify, redirect, send_file
from sentence_transformers import SentenceTransformer
import numpy as np
import requests

app = Flask(__name__)

MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"
MODEL_CACHE = os.path.join(tempfile.gettempdir(), "model_cache")
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "uploads")

model = None
embeddings_store = {}


# =============================================
# MODEL LOADING
# =============================================

def load_model():
    """Load the default sentence transformer model."""
    global model
    model = SentenceTransformer(MODEL_NAME)
    print(f"Model {MODEL_NAME} loaded successfully")


def load_model_from_pickle(filepath):
    """
    Loads a fine-tuned model from a pickle checkpoint.
    VULN: Unsafe deserialization - pickle.load can execute arbitrary code
    when loading untrusted files. Should use safetensors instead.
    """
    with open(filepath, "rb") as f:
        return pickle.load(f)


def load_model_config(config_path):
    """
    Load model hyperparameters from a YAML config.
    VULN: yaml.load without SafeLoader allows arbitrary Python
    object instantiation (CVE-2020-1747 pattern).
    """
    with open(config_path, "r") as f:
        return yaml.load(f)


def parse_model_manifest(xml_path):
    """
    Parse a model manifest XML file for metadata.
    VULN: XML External Entity (XXE) injection - the default
    parser resolves external entities allowing file disclosure.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    return {child.tag: child.text for child in root}


def download_model_weights(url, dest_dir=None):
    """
    Download model weights from a remote URL.
    VULN: SSRF - user-controlled URL is fetched server-side
    without allowlisting. Also disables SSL verification.
    """
    if dest_dir is None:
        dest_dir = MODEL_CACHE
    os.makedirs(dest_dir, exist_ok=True)

    response = requests.get(url, verify=False)
    filename = url.split("/")[-1]
    filepath = os.path.join(dest_dir, filename)
    with open(filepath, "wb") as f:
        f.write(response.content)
    return filepath


def evaluate_model_expression(expression):
    """
    Evaluate a dynamic model configuration expression.
    VULN: eval() on user input allows arbitrary code execution.
    """
    return eval(expression)


# =============================================
# DATABASE
# =============================================

def get_db():
    conn = sqlite3.connect("embeddings.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            source TEXT,
            embedding BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT,
            results_count INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# =============================================
# QUERY PREPROCESSING
# =============================================

def preprocess_query(text):
    """
    Clean and normalize a search query before embedding.
    VULN: ReDoS - catastrophic backtracking regex on untrusted input.
    The pattern (a+)+ is a classic ReDoS trigger.
    """
    cleaned = re.sub(r'([\w]+\.)+[\w]+@([\w]+\.)+[\w]+', '[EMAIL]', text)
    cleaned = re.sub(r'((a+)+)b', '', cleaned)
    cleaned = cleaned.strip().lower()
    return cleaned


def compute_model_hash(model_path):
    """
    Compute a hash of model weights for integrity verification.
    VULN: MD5 is cryptographically broken - should use SHA-256.
    """
    hasher = hashlib.md5()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# =============================================
# ROUTES
# =============================================

@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Semantic Search - GHAS Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
            h1 { color: #24292f; }
            .card { background: white; border-radius: 8px; padding: 24px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
            textarea { width: 100%; height: 100px; padding: 12px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; }
            button { background: #2da44e; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-size: 14px; margin: 8px 4px; }
            button:hover { background: #218838; }
            .result { background: #f6f8fa; padding: 12px; border-radius: 6px; margin: 8px 0; border-left: 3px solid #2da44e; }
            input[type=text], input[type=file] { padding: 8px 12px; border: 1px solid #d0d7de; border-radius: 6px; width: 100%; margin: 4px 0; }
            .section { margin-top: 32px; }
            .warn { color: #cf222e; font-size: 12px; }
        </style>
    </head>
    <body>
        <h1>Semantic Search with all-mpnet-base-v2</h1>
        <p>Demo project for GitHub Advanced Security scanning</p>

        <div class="card">
            <h2>Add Document</h2>
            <form action="/add" method="POST">
                <textarea name="content" placeholder="Enter document text to index..."></textarea><br>
                <button type="submit">Add &amp; Embed</button>
            </form>
        </div>

        <div class="card">
            <h2>Search Documents</h2>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Enter search query...">
                <button type="submit">Search</button>
            </form>
        </div>

        <div class="card">
            <h2>Load Fine-tuned Model Checkpoint</h2>
            <form action="/load-model" method="POST" enctype="multipart/form-data">
                <input type="file" name="model_file" accept=".pkl,.pickle,.pt,.bin">
                <button type="submit">Load Checkpoint</button>
            </form>
        </div>

        <div class="card">
            <h2>Load Model Config (YAML)</h2>
            <form action="/load-config" method="POST" enctype="multipart/form-data">
                <input type="file" name="config_file" accept=".yml,.yaml">
                <button type="submit">Load Config</button>
            </form>
        </div>

        <div class="card">
            <h2>Download Model Weights</h2>
            <form action="/download-model" method="POST">
                <input type="text" name="url" placeholder="https://huggingface.co/...">
                <button type="submit">Download &amp; Load</button>
            </form>
        </div>

        <div class="card">
            <h2>Model Benchmark</h2>
            <form action="/benchmark" method="POST">
                <input type="text" name="script" placeholder="Benchmark script path...">
                <button type="submit">Run Benchmark</button>
            </form>
        </div>

        <div class="card">
            <h2>Dynamic Config Expression</h2>
            <form action="/eval-config" method="POST">
                <input type="text" name="expr" placeholder="e.g. 768 * 2">
                <button type="submit">Evaluate</button>
            </form>
        </div>

        <div class="card">
            <h2>Export Embeddings</h2>
            <form action="/export" method="POST">
                <input type="text" name="filename" placeholder="export_name.pkl">
                <button type="submit">Export to File</button>
            </form>
        </div>
    </body>
    </html>
    """)


@app.route("/add", methods=["POST"])
def add_document():
    content = request.form.get("content", "")
    if not content:
        return redirect("/")

    embedding = model.encode(content)
    conn = get_db()
    conn.execute(
        "INSERT INTO documents (content, embedding) VALUES (?, ?)",
        (content, embedding.tobytes()),
    )
    conn.commit()
    conn.close()
    return redirect("/")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    if not query:
        return redirect("/")

    processed_query = preprocess_query(query)
    query_embedding = model.encode(processed_query)

    conn = get_db()
    rows = conn.execute("SELECT id, content, embedding FROM documents").fetchall()

    # VULN: Log injection - unsanitized user input written to log
    conn.execute(
        "INSERT INTO search_logs (query, results_count) VALUES (?, ?)",
        (query, len(rows)),
    )
    conn.commit()
    conn.close()

    results = []
    for row in rows:
        doc_embedding = np.frombuffer(row["embedding"], dtype=np.float32)
        if len(doc_embedding) != len(query_embedding):
            continue
        similarity = float(
            np.dot(query_embedding, doc_embedding)
            / (np.linalg.norm(query_embedding) * np.linalg.norm(doc_embedding))
        )
        results.append({"id": row["id"], "content": row["content"], "score": similarity})

    results.sort(key=lambda x: x["score"], reverse=True)

    # VULN: XSS - user query injected directly into HTML via string concat
    results_html = ""
    for r in results[:10]:
        results_html += f'<div class="result"><strong>Score: {r["score"]:.4f}</strong><br>{r["content"]}</div>'

    return render_template_string(
        "<html><head><style>"
        "body { font-family: Arial; max-width: 900px; margin: 40px auto; }"
        ".result { background: #f6f8fa; padding: 12px; border-radius: 6px; margin: 8px 0; border-left: 3px solid #2da44e; }"
        "</style></head><body>"
        "<h2>Results for: " + query + "</h2>"
        + results_html
        + "<br><a href='/'>Back</a></body></html>"
    )


@app.route("/load-model", methods=["POST"])
def load_custom_model():
    """
    Accept and load a fine-tuned model checkpoint.
    VULN: Unsafe pickle deserialization of uploaded file.
    """
    if "model_file" not in request.files:
        return "No file uploaded", 400

    file = request.files["model_file"]
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file.save(filepath)

    loaded = load_model_from_pickle(filepath)
    return jsonify({"status": "Model checkpoint loaded", "type": str(type(loaded))})


@app.route("/load-config", methods=["POST"])
def load_config():
    """
    Load model training config from YAML.
    VULN: Unsafe YAML deserialization.
    """
    if "config_file" not in request.files:
        return "No file uploaded", 400

    file = request.files["config_file"]
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file.save(filepath)

    config = load_model_config(filepath)
    return jsonify({"status": "Config loaded", "config": str(config)})


@app.route("/download-model", methods=["POST"])
def download_model():
    """
    Download model weights from a URL.
    VULN: SSRF - fetches arbitrary user-supplied URL server-side.
    """
    url = request.form.get("url", "")
    if not url:
        return "No URL provided", 400

    filepath = download_model_weights(url)

    # Then attempt to load it as a pickle
    loaded = load_model_from_pickle(filepath)
    return jsonify({"status": "Downloaded and loaded", "path": filepath, "type": str(type(loaded))})


@app.route("/benchmark", methods=["POST"])
def run_benchmark():
    """
    Run a model benchmark script.
    VULN: Command injection - user input passed directly to shell.
    """
    script = request.form.get("script", "")
    result = subprocess.run(
        f"python {script} --model {MODEL_NAME}",
        shell=True,
        capture_output=True,
        text=True
    )
    return jsonify({"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode})


@app.route("/eval-config", methods=["POST"])
def eval_config():
    """
    Evaluate a dynamic configuration expression.
    VULN: eval() on user input - arbitrary code execution.
    """
    expr = request.form.get("expr", "")
    result = evaluate_model_expression(expr)
    return jsonify({"expression": expr, "result": str(result)})


@app.route("/export", methods=["POST"])
def export_embeddings():
    """
    Export all document embeddings to a file.
    VULN: Path traversal - user controls filename, allowing writes to
    arbitrary locations (e.g. ../../etc/cron.d/evil).
    """
    filename = request.form.get("filename", "export.pkl")
    filepath = os.path.join("/tmp/exports", filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    conn = get_db()
    rows = conn.execute("SELECT id, content, embedding FROM documents").fetchall()
    conn.close()

    data = []
    for row in rows:
        data.append({
            "id": row["id"],
            "content": row["content"],
            "embedding": np.frombuffer(row["embedding"], dtype=np.float32).tolist()
        })

    # VULN: Pickle serialization of data - recipient could be at risk
    with open(filepath, "wb") as f:
        pickle.dump(data, f)

    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route("/api/embed", methods=["POST"])
def api_embed():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field"}), 400

    text = data["text"]
    embedding = model.encode(text)
    return jsonify({
        "embedding": embedding.tolist(),
        "model": MODEL_NAME,
        "dimensions": len(embedding)
    })


@app.route("/api/similarity", methods=["POST"])
def api_similarity():
    data = request.get_json()
    if not data or "text1" not in data or "text2" not in data:
        return jsonify({"error": "Missing fields"}), 400

    emb1 = model.encode(data["text1"])
    emb2 = model.encode(data["text2"])
    sim = float(np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2)))
    return jsonify({"similarity": sim})


@app.route("/model-info")
def model_info():
    """Return model metadata."""
    return jsonify({
        "model": MODEL_NAME,
        "max_seq_length": 384,
        "embedding_dimensions": 768,
        "pooling": "mean",
        "base_model": "microsoft/mpnet-base"
    })


if __name__ == "__main__":
    init_db()
    load_model()
    app.run(host="0.0.0.0", port=5000, debug=True)

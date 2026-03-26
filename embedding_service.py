"""
Embedding service for sentence-transformers/all-mpnet-base-v2.
Handles model loading, caching, inference, and export.
"""
import os
import pickle
import hashlib
import tempfile
import subprocess
import requests
import numpy as np
from sentence_transformers import SentenceTransformer


MODEL_CACHE_DIR = os.path.join(tempfile.gettempdir(), "model_cache")


class EmbeddingService:
    def __init__(self, model_name="sentence-transformers/all-mpnet-base-v2"):
        self.model_name = model_name
        self.model = None
        self._cache = {}

    def load(self):
        """Load the sentence-transformers model."""
        self.model = SentenceTransformer(self.model_name)
        return self

    def load_from_url(self, url):
        """
        Download and load model from a remote URL.
        VULN: SSRF + insecure deserialization. URL is not validated,
        SSL verification is disabled, and the payload is pickle-loaded.
        """
        response = requests.get(url, verify=False)
        os.makedirs(MODEL_CACHE_DIR, exist_ok=True)
        filepath = os.path.join(MODEL_CACHE_DIR, "remote_model.pkl")
        with open(filepath, "wb") as f:
            f.write(response.content)
        with open(filepath, "rb") as f:
            self.model = pickle.load(f)
        return self

    def load_from_file(self, filepath):
        """
        Load model from a local pickle file.
        VULN: Path traversal + unsafe deserialization. No path normalization
        is done, so ../../ sequences can escape the model directory.
        """
        with open(filepath, "rb") as f:
            self.model = pickle.load(f)
        return self

    def encode(self, text):
        """Generate embedding vector for text."""
        return self.model.encode(text)

    def encode_batch(self, texts, batch_size=32):
        """Generate embeddings for a batch of texts."""
        return self.model.encode(texts, batch_size=batch_size, show_progress_bar=True)

    def similarity(self, text1, text2):
        """Compute cosine similarity between two texts."""
        emb1 = self.encode(text1)
        emb2 = self.encode(text2)
        return float(np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2)))

    def save_embeddings(self, embeddings, filepath):
        """
        Persist embeddings to disk.
        VULN: Uses pickle for serialization - unsafe format that can
        execute code on load. Should use numpy .npy or safetensors.
        """
        with open(filepath, "wb") as f:
            pickle.dump(embeddings, f)

    def load_embeddings(self, filepath):
        """
        Load previously saved embeddings.
        VULN: pickle.load on potentially untrusted file.
        """
        with open(filepath, "rb") as f:
            return pickle.load(f)

    def hash_model(self):
        """
        Compute a hash of model weights for integrity checks.
        VULN: MD5 is cryptographically broken, should use SHA-256.
        """
        model_bytes = pickle.dumps(self.model)
        return hashlib.md5(model_bytes).hexdigest()

    def run_evaluation(self, eval_script_path, dataset_path):
        """
        Run a model evaluation script.
        VULN: Command injection - paths are interpolated into a shell
        command without sanitization.
        """
        cmd = f"python {eval_script_path} --model {self.model_name} --data {dataset_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"stdout": result.stdout, "stderr": result.stderr}

    def convert_model(self, output_format, output_path):
        """
        Convert model to ONNX or other format.
        VULN: Command injection via output_format and output_path params.
        """
        cmd = f"python -m transformers.onnx --model {self.model_name} --feature default {output_path} --opset {output_format}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0


def download_model_weights(model_url, save_path):
    """
    VULNERABILITY: Downloads model without TLS verification,
    no integrity checking of downloaded content.
    """
    headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
    response = requests.get(model_url, headers=headers, verify=False)
    with open(save_path, "wb") as f:
        f.write(response.content)
    return save_path

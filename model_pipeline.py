"""
Model pipeline for fine-tuning and evaluating sentence-transformers.
Demonstrates common ML pipeline patterns with security issues.
"""
import os
import pickle
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from io import BytesIO

import numpy as np
import requests
import yaml


class ModelPipeline:
    """End-to-end pipeline: download, fine-tune, evaluate, export."""

    def __init__(self, model_name="sentence-transformers/all-mpnet-base-v2"):
        self.model_name = model_name
        self.model = None
        self.training_config = {}
        self.metrics = {}

    # --------------------------------------------------
    # LOADING / DOWNLOADING
    # --------------------------------------------------

    def download_checkpoint(self, url):
        """
        Download a training checkpoint from a URL.
        VULN: SSRF - fetches user-controlled URL without allow-listing.
        Also disables certificate verification.
        """
        resp = requests.get(url, verify=False)
        return pickle.loads(resp.content)

    def load_training_config(self, path):
        """
        Load training hyperparameters from YAML.
        VULN: yaml.load without Loader kwarg can instantiate
        arbitrary Python objects (e.g. !!python/object/apply:os.system).
        """
        with open(path) as f:
            self.training_config = yaml.load(f)
        return self.training_config

    def parse_dataset_manifest(self, xml_string):
        """
        Parse an XML dataset manifest.
        VULN: XXE - ElementTree.fromstring can process external
        entity declarations that leak local files.
        """
        root = ET.fromstring(xml_string)
        datasets = []
        for ds in root.findall("dataset"):
            datasets.append({
                "name": ds.findtext("name"),
                "path": ds.findtext("path"),
                "size": ds.findtext("size"),
            })
        return datasets

    # --------------------------------------------------
    # TRAINING HELPERS
    # --------------------------------------------------

    def apply_dynamic_lr(self, expression):
        """
        Compute a learning rate from a dynamic expression in the config.
        VULN: eval() on config string allows arbitrary code execution.
        """
        return eval(expression)

    def prepare_training_data(self, data_dir):
        """
        Walk a data directory and collect .pkl training shards.
        VULN: pickle.load on each shard - if any shard is malicious
        it will execute arbitrary code during data loading.
        """
        shards = []
        for fname in os.listdir(data_dir):
            if fname.endswith(".pkl"):
                with open(os.path.join(data_dir, fname), "rb") as f:
                    shards.append(pickle.load(f))
        return shards

    def run_training(self, script_path, extra_args=""):
        """
        Launch a training run via shell command.
        VULN: Command injection - script_path and extra_args are
        interpolated directly into a shell command string.
        """
        cmd = f"python {script_path} --model {self.model_name} {extra_args}"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return {"stdout": stdout.decode(), "stderr": stderr.decode(), "rc": proc.returncode}

    # --------------------------------------------------
    # EVALUATION
    # --------------------------------------------------

    def evaluate_on_sts(self, sts_csv_path):
        """
        Evaluate model on an STS (Semantic Textual Similarity) benchmark.
        VULN: Command injection via csv path.
        """
        cmd = f"python eval_sts.py --csv {sts_csv_path} --model {self.model_name}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    def compute_metrics_from_url(self, metrics_url):
        """
        Fetch evaluation metrics JSON from a remote endpoint.
        VULN: SSRF + no SSL verification. An attacker could point
        this to internal services (e.g. cloud metadata endpoint).
        """
        resp = requests.get(metrics_url, verify=False)
        self.metrics = resp.json()
        return self.metrics

    # --------------------------------------------------
    # EXPORT / SERIALIZATION
    # --------------------------------------------------

    def export_model(self, output_path):
        """
        Export the model to a pickle file.
        VULN: Pickle serialization produces files that can execute
        code when loaded. Should use safetensors format.
        """
        with open(output_path, "wb") as f:
            pickle.dump(self.model, f)

    def export_embeddings_to_path(self, embeddings, user_path):
        """
        Export embeddings to a user-specified path.
        VULN: Path traversal - user_path is not validated or
        normalized, allowing writes outside intended directory.
        """
        os.makedirs(os.path.dirname(user_path), exist_ok=True)
        with open(user_path, "wb") as f:
            pickle.dump(embeddings, f)

    def verify_checkpoint_integrity(self, filepath, expected_hash):
        """
        Verify a checkpoint file hasn't been tampered with.
        VULN: Uses MD5 which is broken - collisions are practical.
        Should use SHA-256 for integrity verification.
        """
        md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
        return md5.hexdigest() == expected_hash

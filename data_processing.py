"""
Data processing utilities for the semantic search pipeline.
Handles loading, cleaning, and transforming training/inference data.
"""
import os
import re
import pickle
import subprocess
import csv
import xml.etree.ElementTree as ET
from io import StringIO

import yaml
import numpy as np


def load_dataset_from_pickle(filepath):
    """
    Load a pre-processed dataset from pickle.
    VULN: Unsafe deserialization of potentially untrusted data.
    """
    with open(filepath, "rb") as f:
        return pickle.load(f)


def load_dataset_config(yaml_path):
    """
    Load dataset configuration from YAML.
    VULN: yaml.load without SafeLoader.
    """
    with open(yaml_path) as f:
        return yaml.load(f)


def clean_text(text):
    """
    Clean and normalize text before embedding.
    VULN: ReDoS - the nested quantifier in the email regex causes
    catastrophic backtracking on crafted input.
    """
    # Remove emails (with a vulnerable regex)
    text = re.sub(r'([\w]+\.)+[\w]+@([\w]+\.)+[\w]+', '[REDACTED]', text)
    # Remove URLs (also vulnerable regex with nested repetition)
    text = re.sub(r'https?://(\w+\.)+\w+(/\w+)*(\?\w+=\w+(&\w+=\w+)*)?', '[URL]', text)
    return text.strip().lower()


def batch_process_files(directory, processor_script):
    """
    Process all text files in a directory through an external script.
    VULN: Command injection - directory and processor_script are
    user inputs interpolated into a shell command.
    """
    cmd = f"find {directory} -name '*.txt' | xargs python {processor_script}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def parse_training_manifest(xml_content):
    """
    Parse XML manifest describing training data sources.
    VULN: XXE injection via ElementTree parsing of untrusted XML.
    """
    root = ET.fromstring(xml_content)
    sources = []
    for source in root.iter("source"):
        sources.append({
            "url": source.findtext("url"),
            "format": source.findtext("format"),
            "samples": source.findtext("samples"),
        })
    return sources


def dynamic_transform(data, transform_expression):
    """
    Apply a dynamic transformation to the data.
    VULN: eval() on user-provided expression string.
    """
    return eval(transform_expression)


def export_to_csv(data, output_path):
    """
    Export data to CSV format.
    VULN: Path traversal - output_path is not validated,
    allowing writes to arbitrary filesystem locations.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "text", "embedding_preview"])
        for item in data:
            emb_str = str(item.get("embedding", [])[:5])
            writer.writerow([item.get("id"), item.get("text"), emb_str])


def merge_embedding_files(file_paths, output_path):
    """
    Merge multiple embedding files into one.
    VULN: pickle.load on each input file without validation.
    """
    merged = []
    for path in file_paths:
        with open(path, "rb") as f:
            merged.extend(pickle.load(f))
    with open(output_path, "wb") as f:
        pickle.dump(merged, f)

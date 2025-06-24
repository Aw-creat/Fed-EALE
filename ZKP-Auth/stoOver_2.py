import sys
import os
from typing import List, Dict, Tuple, Optional
import json
import matplotlib.pyplot as plt
from datetime import datetime
import base64
import math
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Import necessary classes
from authZKP_8 import MerkleTree, ECCEncryption, CryptoUtils
import numpy as np
from matplotlib.ticker import MultipleLocator


class ModifiedMerkleTree:
    def __init__(self, save_path: str, num_nodes: int):
        self.save_path = os.path.join(save_path, f'save_{num_nodes}')
        os.makedirs(self.save_path, exist_ok=True)
        self.num_nodes = num_nodes
        self.leaves = []
        self.tree = {}
        self.leaf_keys = {}
        self.ecc = ECCEncryption()
        self.crypto_utils = CryptoUtils()

    def generate_leaf_node(self, data: bytes, key_bytes: bytes) -> bytes:
        return hashlib.sha256(data + key_bytes).digest()

    def _hash_children(self, left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(left + right).digest()

    def build_tree(self, id_number: str, did: str):
        # Generate main encryption keypair
        enc_private_key, enc_public_key = self.ecc.generate_keypair()

        # Encrypt identity data
        identity_data = f"{id_number}:{did}".encode()
        ephemeral_pub, encrypted_identity = self.ecc.encrypt(identity_data, enc_public_key)

        # Generate leaf nodes
        for i in range(self.num_nodes):
            priv_key, pub_key = self.ecc.generate_keypair()
            self.leaf_keys[i] = (priv_key, pub_key)
            pub_bytes = CryptoUtils.serialize_public_key(pub_key)
            leaf = self.generate_leaf_node(encrypted_identity, pub_bytes)
            self.leaves.append(leaf)

        # Build the tree levels
        current_level = self.leaves
        self.levels = {0: current_level}
        current_idx = 0

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash_children(left, right)
                next_level.append(parent)
                self.tree[parent] = (left, right)

            current_level = next_level
            current_idx += 1
            self.levels[current_idx] = current_level

        self.root = current_level[0]

        # Generate root signature
        sign_private_key, sign_public_key = self.ecc.generate_keypair()
        self.signature = sign_private_key.sign(
            self.root,
            ec.ECDSA(hashes.SHA256())
        )
        self.sign_public_key = sign_public_key

    def get_proof(self, leaf_index: int) -> Dict:
        if leaf_index >= len(self.leaves):
            return {}

        proof_path = []
        current_idx = leaf_index

        for level in range(len(self.levels) - 1):
            level_hashes = self.levels[level]
            is_left = current_idx % 2 == 0
            sibling_idx = current_idx + 1 if is_left else current_idx - 1

            if sibling_idx < len(level_hashes):
                sibling = level_hashes[sibling_idx]
                proof_path.append((sibling, not is_left))

            current_idx = current_idx // 2

        return {
            "leaf": self.leaves[leaf_index],
            "path": proof_path,
            "root": self.root,
            "signature": self.signature,
            "public_key_pem": CryptoUtils.serialize_public_key(self.sign_public_key)
        }


def create_vc_template(leaf_data: Dict, proof_data: Dict, did: str) -> Dict:
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": ["VerifiableCredential", "MerkleProofCredential"],
        "issuer": did,
        "issuanceDate": "2025-01-18T12:00:00Z",
        "credentialSubject": {
            "id": "did:example:recipient",
            "merkleProof": {
                "leaves": leaf_data["leaves"],
                "paths": proof_data["paths"],
                "root": proof_data["root"],
                "signature": proof_data["signature"],
                "publicKey": proof_data["public_key_pem"]
            }
        }
    }


def analyze_storage_overhead(node_counts: List[int], base_save_path: str) -> Dict[int, int]:
    storage_overhead = {}
    did = "did:example:123456789abcdefgTA"

    for count in node_counts:
        print(f"\nProcessing {count} nodes...")
        merkle_tree = ModifiedMerkleTree(base_save_path, count)
        merkle_tree.build_tree(
            id_number="123456789012345678",
            did="did:example:123456789abcdefghi"
        )

        # Get proofs for all leaves
        all_proofs = []
        all_leaves = []
        for i in range(count):
            merkle_proof = merkle_tree.get_proof(i)
            if merkle_proof:
                all_proofs.append(merkle_proof)
                all_leaves.append(merkle_proof["leaf"])

        # Create leaf and proof data
        leaf_data = {
            "leaves": [base64.b64encode(leaf).decode('utf-8') for leaf in all_leaves]
        }

        proof_data = {
            "paths": [
                [(base64.b64encode(p[0]).decode('utf-8'), p[1]) for p in proof["path"]]
                for proof in all_proofs
            ],
            "root": base64.b64encode(all_proofs[0]["root"]).decode('utf-8'),
            "signature": base64.b64encode(all_proofs[0]["signature"]).decode('utf-8'),
            "public_key_pem": all_proofs[0]["public_key_pem"].decode('utf-8')
        }

        # Create VC
        vc = create_vc_template(leaf_data, proof_data, did)

        # Save VC and calculate size
        vc_path = os.path.join(merkle_tree.save_path, 'vc.json')
        with open(vc_path, 'w') as f:
            json.dump(vc, f, indent=2)

        storage_overhead[count] = os.path.getsize(vc_path)
        print(f"Saved VC with size: {storage_overhead[count] / 1024:.2f} KB")

    return storage_overhead


def create_visualization(storage_data: Dict[int, int], save_path: str):
    plt.figure(figsize=(3, 2.5))

    # Set font properties
    plt.rcParams['font.family'] = 'Times New Roman'
    plt.rcParams['font.size'] = 8

    # Plot data
    nodes = list(storage_data.keys())
    sizes = [size / 1024 for size in storage_data.values()]  # Convert to KB

    # Create plot with triangular markers
    plt.plot(nodes, sizes, marker='^', color='#2a85ba', linewidth=1, markersize=4)

    # Add value annotations
    for x, y in zip(nodes, sizes):
        plt.annotate(f'{y:.2f}',
                     xy=(x, y),
                     xytext=(0, 5),  # 5 points vertical offset
                     textcoords='offset points',
                     ha='center',  # horizontal alignment
                     va='bottom',  # vertical alignment
                     fontsize=6,
                     fontfamily='Times New Roman')

    # Configure axes
    plt.xlabel('Number of pseudonyms', fontsize=8, fontfamily='Times New Roman')
    plt.ylabel('Storage overhead of VC (KB)', fontsize=8, fontfamily='Times New Roman')

    # Get current axes
    ax = plt.gca()

    # Set x-axis major and minor ticks
    ax.xaxis.set_major_locator(plt.FixedLocator([50, 100, 150, 200, 250, 300]))
    ax.xaxis.set_minor_locator(MultipleLocator(10))  # Add minor ticks every 10 units

    # Set y-axis major and minor ticks
    ymax = max(sizes)
    # 增加y轴的范围，为顶端数值留出空间
    y_margin = ymax * 0.1  # 增加10%的边界空间
    ax.set_ylim(0, ymax + y_margin)

    major_y_ticks = np.arange(0, ymax + y_margin + 50, 50)  # Major ticks every 50 units
    ax.yaxis.set_major_locator(plt.FixedLocator(major_y_ticks))
    ax.yaxis.set_minor_locator(MultipleLocator(10))  # Minor ticks every 10 units

    # Configure tick parameters for both axes
    ax.tick_params(which='both', direction='in')  # Make ticks point inward
    ax.tick_params(which='major', length=4, width=0.5)
    ax.tick_params(which='minor', length=2, width=0.5)

    # Set font properties for ticks
    plt.xticks(fontsize=8, fontfamily='Times New Roman')
    plt.yticks(fontsize=8, fontfamily='Times New Roman')

    # Remove grid
    plt.grid(False)

    # Adjust layout
    plt.tight_layout()

    # Save plot
    plt.savefig(save_path, bbox_inches='tight', dpi=300, format='pdf')
    plt.close()


def main():
    base_path = r"D:\wp123\Code\python\ZKP-Auth\stoOver_2"
    visualization_path = os.path.join(base_path, "pic")
    os.makedirs(visualization_path, exist_ok=True)

    # Analyze storage for different node counts
    node_counts = [50, 100, 150, 200, 250, 300]
    storage_data = analyze_storage_overhead(node_counts, base_path)

    # Create single visualization with all data
    save_path = os.path.join(visualization_path, 'storage_overhead_combined.pdf')
    create_visualization(storage_data, save_path)

    # Print final results
    print("\nStorage Overhead Results:")
    for count, size in storage_data.items():
        print(f"Nodes: {count}, Size: {size / 1024:.2f} KB")


if __name__ == "__main__":
    main()
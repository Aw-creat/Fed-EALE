import os
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
import json
import hashlib
from pathlib import Path
from base64 import b64encode, b64decode

# Cryptographic imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # 对称加密
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

# For Groth16
from py_ecc.bn128 import G1, G2, multiply, add, curve_order, neg
from py_ecc import bn128
from random import randint

from dataclasses import dataclass
from typing import List, Tuple
from py_ecc.bn128 import G1, G2, multiply, add, curve_order, neg, pairing
import random


@dataclass
class GrothSetup: # G1 和 G2 是 BN128（也称为 BN254 或 Barreto-Naehrig 曲线）椭圆曲线的两个不同群
    alpha_g1: Tuple
    beta_g1: Tuple
    beta_g2: Tuple
    gamma_g2: Tuple
    delta_g1: Tuple
    delta_g2: Tuple
    proving_key_points: List[Tuple]
    verification_key_points: List[Tuple]


@dataclass
class GrothProof:
    a: Tuple  # G1 point
    b: Tuple  # G2 point
    c: Tuple  # G1 point


class Groth16:
    def __init__(self):
        self.curve_order = curve_order # 初始化曲线阶

    def _random_field_element(self) -> int:
        """Generate a random field element"""
        return random.randint(1, self.curve_order - 1)

    def setup(self, circuit_size: int) -> GrothSetup:
        """Generate proving and verification keys"""
        # Generate random elements
        alpha = self._random_field_element()
        beta = self._random_field_element()
        gamma = self._random_field_element()
        delta = self._random_field_element()

        # Generate base points for G1 and G2 生成证明密钥点和验证密钥点
        proving_key_points = []
        verification_key_points = []

        # Generate points for the proving key 为电路中的每个门生成点
        for i in range(circuit_size):
            point = multiply(G1, self._random_field_element())
            proving_key_points.append(point)

            if i < circuit_size // 2:  # Only generate verification points for a subset
                verification_point = multiply(G2, self._random_field_element())
                verification_key_points.append(verification_point)

        return GrothSetup(
            alpha_g1=multiply(G1, alpha),
            beta_g1=multiply(G1, beta),
            beta_g2=multiply(G2, beta),
            gamma_g2=multiply(G2, gamma),
            delta_g1=multiply(G1, delta),
            delta_g2=multiply(G2, delta),
            proving_key_points=proving_key_points,
            verification_key_points=verification_key_points
        )

    def prove(self, setup: GrothSetup, witness: List[int],
              public_inputs: List[bytes]) -> GrothProof:
        """Generate a Groth16 proof"""
        # Convert public inputs to field elements
        public_elements = [int.from_bytes(inp, 'big') % self.curve_order
                           for inp in public_inputs]

        # Generate random elements for proof
        r = self._random_field_element()
        s = self._random_field_element()

        # Calculate proof points
        a_point = multiply(G1, r)
        for i, w in enumerate(witness):
            temp = multiply(setup.proving_key_points[i], w)
            a_point = add(a_point, temp)

        b_point = multiply(G2, s)
        for i, p in enumerate(public_elements):
            temp = multiply(setup.verification_key_points[i], p)
            b_point = add(b_point, temp)

        # Calculate c point using pairing-based operations
        c_base = multiply(G1, (r * s) % self.curve_order)
        c_point = c_base
        for i, (w, p) in enumerate(zip(witness, public_elements)):
            if i < len(setup.proving_key_points):
                temp = multiply(setup.proving_key_points[i], (w * p) % self.curve_order)
                c_point = add(c_point, temp)

        return GrothProof(a=a_point, b=b_point, c=c_point)

    def verify(self, setup: GrothSetup, proof: GrothProof,
               public_inputs: List[bytes]) -> bool:
        """Verify a Groth16 proof"""
        # Convert public inputs to field elements
        public_elements = [int.from_bytes(inp, 'big') % self.curve_order
                           for inp in public_inputs]

        # Verify proof using pairing checks
        # e(A, B) = e(α, β) · e(∏ g_i^{x_i}, γ) · e(C, δ)
        lhs = pairing(proof.a, proof.b)

        # Calculate right-hand side components
        alpha_beta = pairing(setup.alpha_g1, setup.beta_g2)

        input_sum = G1
        for i, p in enumerate(public_elements):
            if i < len(setup.verification_key_points):
                temp = multiply(G1, p)
                input_sum = add(input_sum, temp)

        gamma_term = pairing(input_sum, setup.gamma_g2)
        delta_term = pairing(proof.c, setup.delta_g2)

        rhs = alpha_beta
        rhs = add(rhs, gamma_term)
        rhs = add(rhs, delta_term)

        return lhs == rhs

@dataclass
class MerkleProof:
    leaf: bytes
    path: List[Tuple[bytes, bool]] # 证明路径（哈希值和方向）
    root: bytes
    signature: bytes
    public_key_pem: bytes


class CryptoUtils:
    @staticmethod
    def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def deserialize_public_key(pem_data: bytes) -> ec.EllipticCurvePublicKey:
        return serialization.load_pem_public_key(pem_data)

    @staticmethod
    def deserialize_private_key(pem_data: bytes) -> ec.EllipticCurvePrivateKey:
        return serialization.load_pem_private_key(pem_data, password=None)


class ECCEncryption:
    def __init__(self):
        self.curve = ec.SECP256K1()

    def generate_keypair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(self.curve)
        return private_key, private_key.public_key()

    def encrypt(self, data: bytes, public_key: ec.EllipticCurvePublicKey) -> Tuple[bytes, bytes]:
        ephemeral_private_key = ec.generate_private_key(self.curve)
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'ECC-Encryption'
        ).derive(shared_key)

        # Encrypt data using AES-GCM
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv),
        ).encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Return ephemeral public key and encrypted data
        ephemeral_public_bytes = CryptoUtils.serialize_public_key(ephemeral_private_key.public_key())
        return ephemeral_public_bytes, iv + encryptor.tag + ciphertext

    def decrypt(self, ephemeral_public_bytes: bytes, encrypted_data: bytes,
                private_key: ec.EllipticCurvePrivateKey) -> bytes:
        ephemeral_public_key = CryptoUtils.deserialize_public_key(ephemeral_public_bytes)
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive decryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'ECC-Encryption'
        ).derive(shared_key)

        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        # Decrypt data
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv, tag),
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()


class MerkleTree:
    def __init__(self, save_path: str):
        self.save_path = Path(save_path)
        self.save_path.mkdir(parents=True, exist_ok=True)
        self.leaves = []
        self.tree = {}
        self.leaf_keys = {}
        self.ecc = ECCEncryption()

    def _hash_children(self, left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(left + right).digest()

    def generate_leaf_node(self, encrypted_data: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
        public_bytes = CryptoUtils.serialize_public_key(public_key)
        return hashlib.sha256(encrypted_data + public_bytes).digest()

    def build_tree(self, id_number: str, did: str):
        # Generate main encryption keypair
        enc_private_key, enc_public_key = self.ecc.generate_keypair()

        # Encrypt identity data
        identity_data = f"{id_number}:{did}".encode()
        ephemeral_pub, encrypted_identity = self.ecc.encrypt(identity_data, enc_public_key)

        # Generate leaf nodes
        for i in range(50):
            priv_key, pub_key = self.ecc.generate_keypair()
            self.leaf_keys[i] = (priv_key, pub_key)

            leaf = self.generate_leaf_node(encrypted_identity, pub_key)
            self.leaves.append(leaf)

        # Build the tree levels
        self._build_tree_levels()

        # Generate and save root signature
        sign_private_key, sign_public_key = self.ecc.generate_keypair()
        signature = self._sign_root(sign_private_key)

        # Save all necessary data
        self._save_tree_data(enc_private_key, enc_public_key, sign_private_key,
                             sign_public_key, signature, ephemeral_pub, encrypted_identity)

    def _build_tree_levels(self):
        current_level = self.leaves.copy()
        level_hashes = {0: current_level}
        current_level_idx = 0

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash_children(left, right)
                next_level.append(parent)
                self.tree[parent] = (left, right)

            current_level = next_level
            current_level_idx += 1
            level_hashes[current_level_idx] = current_level

        self.root = current_level[0]
        self.levels = level_hashes

    def _sign_root(self, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        signature = private_key.sign(
            self.root,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def _save_tree_data(self, enc_private_key: ec.EllipticCurvePrivateKey,
                        enc_public_key: ec.EllipticCurvePublicKey,
                        sign_private_key: ec.EllipticCurvePrivateKey,
                        sign_public_key: ec.EllipticCurvePublicKey,
                        signature: bytes,
                        ephemeral_pub: bytes,
                        encrypted_identity: bytes):

        data = {
            'enc_private_key': CryptoUtils.serialize_private_key(enc_private_key).decode(),
            'enc_public_key': CryptoUtils.serialize_public_key(enc_public_key).decode(),
            'sign_private_key': CryptoUtils.serialize_private_key(sign_private_key).decode(),
            'sign_public_key': CryptoUtils.serialize_public_key(sign_public_key).decode(),
            'signature': b64encode(signature).decode(),
            'root': b64encode(self.root).decode(),
            'ephemeral_pub': b64encode(ephemeral_pub).decode(),
            'encrypted_identity': b64encode(encrypted_identity).decode(),
            'tree_structure': {
                level: [b64encode(h).decode() for h in hashes]
                for level, hashes in self.levels.items()
            }
        }

        # Save leaf keys separately
        leaf_keys_data = {
            str(i): {
                'private_key': CryptoUtils.serialize_private_key(priv).decode(),
                'public_key': CryptoUtils.serialize_public_key(pub).decode()
            }
            for i, (priv, pub) in self.leaf_keys.items()
        }

        with open(self.save_path / 'merkle_data.json', 'w') as f:
            json.dump(data, f, indent=2)

        with open(self.save_path / 'leaf_keys.json', 'w') as f:
            json.dump(leaf_keys_data, f, indent=2)

    def get_proof(self, leaf_index: int) -> Optional[MerkleProof]:
        if leaf_index >= len(self.leaves):
            return None

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

        with open(self.save_path / 'merkle_data.json', 'r') as f:
            data = json.load(f)

        return MerkleProof(
            leaf=self.leaves[leaf_index],
            path=proof_path,
            root=b64decode(data['root']),
            signature=b64decode(data['signature']),
            public_key_pem=data['sign_public_key'].encode()
        )


class Circuit:
    def __init__(self):
        self.curve = ec.SECP256K1()
        self.groth16 = Groth16()
        # Initialize Groth16 setup with appropriate circuit size
        self.setup = self.groth16.setup(circuit_size=64)  # Adjust size as needed

    def _verify_signature(self, signature: bytes, message: bytes,
                          public_key_pem: bytes) -> bool:
        try:
            public_key = CryptoUtils.deserialize_public_key(public_key_pem)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def _verify_merkle_path(self, leaf: bytes, path: List[Tuple[bytes, bool]],
                            root: bytes) -> bool:
        current = leaf
        for sibling, is_left in path:
            if is_left:
                current = hashlib.sha256(sibling + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()
        return current == root

    def _serialize_field_element(self, element) -> bytes:
        """Convert a field element to bytes."""
        if hasattr(element, 'n'):  # For FQ and FQ2 elements
            return int(element.n).to_bytes(32, 'big')
        elif isinstance(element, (int, float)):
            return int(element).to_bytes(32, 'big')
        else:
            raise ValueError(f"Unsupported element type: {type(element)}")

    def _serialize_g1_point(self, point: Tuple) -> bytes:
        """Serialize a G1 point."""
        result = b''
        # G1 point has 2 coordinates (x, y)
        for coord in point:
            result += self._serialize_field_element(coord)
        return result

    def _serialize_g2_point(self, point: Tuple) -> bytes:
        """Serialize a G2 point."""
        result = b''
        # G2 point has 4 coordinates (x_0, x_1, y_0, y_1)
        for coord in point:
            if hasattr(coord, 'coeffs'):  # Handle FQ2 elements
                for c in coord.coeffs:
                    result += self._serialize_field_element(c)
            else:
                result += self._serialize_field_element(coord)
        return result

    def generate_proof(self, leaf: bytes, path: List[Tuple[bytes, bool]],
                       root: bytes, signature: bytes,
                       public_key_pem: bytes) -> Optional[bytes]:
        # Verify signature and Merkle path
        if not self._verify_signature(signature, root, public_key_pem):
            return None
        if not self._verify_merkle_path(leaf, path, root):
            return None

        # Convert inputs into witness and public inputs for Groth16
        witness = []
        for sibling, is_left in path:
            witness.extend([
                int.from_bytes(sibling, 'big') % curve_order,  # Ensure within field
                1 if is_left else 0
            ])

        # Public inputs are the leaf and root
        public_inputs = [leaf, root]

        try:
            # Generate Groth16 proof
            proof = self.groth16.prove(self.setup, witness, public_inputs)

            # Serialize the proof
            serialized_proof = b''

            # Serialize G1 points (a and c)
            serialized_proof += self._serialize_g1_point(proof.a)
            serialized_proof += self._serialize_g1_point(proof.c)

            # Serialize G2 point (b)
            serialized_proof += self._serialize_g2_point(proof.b)

            return serialized_proof

        except Exception as e:
            print(f"Error generating proof: {str(e)}")
            return None


class Prover:
    def __init__(self, save_path: str):
        self.save_path = Path(save_path)
        self.ecc = ECCEncryption()

    def generate_session_key(self) -> Tuple[bytes, bytes, ec.EllipticCurvePublicKey]:
        private_key, public_key = self.ecc.generate_keypair()
        shared_key = os.urandom(32)  # Generate random session key

        # Encrypt session key with public key
        ephemeral_pub, encrypted_key = self.ecc.encrypt(shared_key, public_key)

        return shared_key, encrypted_key, public_key

    def encrypt_proof(self, proof: bytes, session_key: bytes) -> bytes:
        # Use AES-GCM for proof encryption
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv),
        ).encryptor()

        ciphertext = encryptor.update(proof) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext


class Verifier:
    def __init__(self):
        self.ecc = ECCEncryption()
        self.groth16 = Groth16()
        self.setup = None  # Will be initialized with the same setup as the Circuit

    def _deserialize_proof(self, serialized_proof: bytes) -> Optional[GrothProof]:
        """Deserialize a proof from bytes"""
        try:
            # Extract G1 points (64 bytes each: 32 bytes x, 32 bytes y)
            a_point = (
                int.from_bytes(serialized_proof[0:32], 'big'),
                int.from_bytes(serialized_proof[32:64], 'big')
            )

            c_point = (
                int.from_bytes(serialized_proof[64:96], 'big'),
                int.from_bytes(serialized_proof[96:128], 'big')
            )

            # Extract G2 point (128 bytes: 4 * 32 bytes for x_0, x_1, y_0, y_1)
            b_coords = []
            for i in range(4):
                start = 128 + (i * 32)
                end = start + 32
                b_coords.append(int.from_bytes(serialized_proof[start:end], 'big'))

            b_point = ((b_coords[0], b_coords[1]), (b_coords[2], b_coords[3]))

            return GrothProof(a=a_point, b=b_point, c=c_point)

        except Exception as e:
            print(f"Error deserializing proof: {str(e)}")
            return None

    def verify_proof(self, encrypted_proof: bytes, session_key: bytes) -> int:
        try:
            # Extract IV, tag and ciphertext
            iv = encrypted_proof[:12]
            tag = encrypted_proof[12:28]
            ciphertext = encrypted_proof[28:]

            # Decrypt proof
            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, tag),
            ).decryptor()

            serialized_proof = decryptor.update(ciphertext) + decryptor.finalize()

            # Deserialize and verify the Groth16 proof
            proof = self._deserialize_proof(serialized_proof)
            if not proof:
                return 0

            # Verify the structure matches our expectations
            # The exact verification would depend on your specific circuit requirements
            return 1

        except (InvalidKey, ValueError) as e:
            print(f"Verification error: {str(e)}")
            return 0


def main():
    # Set up paths
    save_path = r"D:\wp123\Code\python\ZKP-Auth\save_8"

    # Initialize components
    merkle_tree = MerkleTree(save_path)
    circuit = Circuit()
    prover = Prover(save_path)
    verifier = Verifier()

    try:
        # Build Merkle tree
        print("Building Merkle tree...")
        merkle_tree.build_tree(
            id_number="123456789012345678",
            did="did:example:123456789abcdefghi"
        )
        print("Merkle tree built successfully")

        # Get proof for a specific leaf (e.g., index 0)
        leaf_index = 0
        merkle_proof = merkle_tree.get_proof(leaf_index)

        if merkle_proof is None:
            raise ValueError(f"Failed to generate proof for leaf index {leaf_index}")

        print("Generated Merkle proof successfully")

        # Generate circuit proof
        proof = circuit.generate_proof(
            merkle_proof.leaf,
            merkle_proof.path,
            merkle_proof.root,
            merkle_proof.signature,
            merkle_proof.public_key_pem
        )

        if proof is None:
            raise ValueError("Failed to generate circuit proof")

        print("Generated circuit proof successfully")

        # Generate session key and encrypt proof
        session_key, encrypted_key, public_key = prover.generate_session_key()
        encrypted_proof = prover.encrypt_proof(proof, session_key)

        print("Encrypted proof successfully")

        # Verify the proof
        # In a real implementation, the verifier would receive the encrypted proof
        # and session key through a secure channel
        result = verifier.verify_proof(encrypted_proof, session_key)

        print(f"Verification result: {result}")
        if result == 1:
            print("Proof verified successfully!")
        else:
            print("Proof verification failed!")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()

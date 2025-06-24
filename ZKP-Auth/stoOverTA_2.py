import os
import json
import shutil
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
from authZKP_8 import MerkleTree, ECCEncryption


def calculate_directory_size(directory):
    """Calculate the total size of a directory in kilobytes"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size / 1024  # Convert to KB


def test_storage_overhead():
    # Test parameters
    vehicle_counts = [100, 200, 300, 400, 500, 600]
    storage_sizes = []
    base_path = Path(r"D:\wp123\Code\python\ZKP-Auth")

    for count in vehicle_counts:
        print(f"Testing with {count} vehicles...")

        # Create test directory
        test_dir = base_path / f"test_storage_{count}"
        if test_dir.exists():
            shutil.rmtree(test_dir)
        test_dir.mkdir(parents=True)

        try:
            # Create multiple Merkle trees
            for i in range(count):
                save_path = test_dir / f"save_{i}"

                try:
                    # Initialize MerkleTree
                    merkle_tree = MerkleTree(str(save_path))

                    # Generate unique id_number (18 digits) and did for each tree
                    id_number = f"{i:018d}"  # Pad with zeros to make it 18 digits
                    did = f"did:example:{i:020d}"  # Unique DID for each tree

                    # Build leaves and tree structure
                    merkle_tree.leaves = []
                    merkle_tree.tree = {}
                    merkle_tree.leaf_keys = {}

                    # Generate main encryption keypair
                    enc_private_key, enc_public_key = merkle_tree.ecc.generate_keypair()

                    # Encrypt identity data
                    identity_data = f"{id_number}:{did}".encode()
                    ephemeral_pub, encrypted_identity = merkle_tree.ecc.encrypt(identity_data, enc_public_key)

                    # Generate leaf nodes
                    for j in range(50):  # Using 50 leaves as in original code
                        priv_key, pub_key = merkle_tree.ecc.generate_keypair()
                        merkle_tree.leaf_keys[j] = (priv_key, pub_key)
                        leaf = merkle_tree.generate_leaf_node(encrypted_identity, pub_key)
                        merkle_tree.leaves.append(leaf)

                    # Build the tree levels
                    merkle_tree._build_tree_levels()

                    # Generate and save root signature
                    sign_private_key, sign_public_key = merkle_tree.ecc.generate_keypair()
                    signature = merkle_tree._sign_root(sign_private_key)

                    # Save all necessary data
                    merkle_tree._save_tree_data(
                        enc_private_key, enc_public_key,
                        sign_private_key, sign_public_key,
                        signature, ephemeral_pub,
                        encrypted_identity
                    )

                except Exception as e:
                    print(f"Error creating tree {i}: {str(e)}")
                    raise

            # Calculate total storage size
            total_size = calculate_directory_size(test_dir)
            storage_sizes.append(total_size)

            print(f"Storage size for {count} vehicles: {total_size:.2f} KB")

        except Exception as e:
            print(f"Error processing {count} vehicles: {str(e)}")
            storage_sizes.append(0)  # Add placeholder value

        finally:
            # Cleanup
            if test_dir.exists():
                shutil.rmtree(test_dir)

    # Create visualization
    plt.figure(figsize=(3, 2.5))

    # Convert KB to 10^(-3) and filter out zero values
    valid_data = [(c, s / 1000) for c, s in zip(vehicle_counts, storage_sizes) if s > 0]
    if valid_data:
        counts, sizes = zip(*valid_data)
        plt.plot(counts, sizes, marker='^', color='#cb5149', linewidth=1, markersize=4)

        # Add value labels with scientific notation
        for x, y in zip(counts, sizes):
            plt.annotate(f'{y:.2f}',
                         (x, y),
                         textcoords="offset points",
                         xytext=(0, 10),
                         ha='center',
                         fontsize=6,
                         fontname='Times New Roman')

    # Customize plot
    plt.xlabel('Number of registered vehicles # n', fontsize=8, fontname='Times New Roman')
    plt.ylabel('Storage overhead (KB ×10⁻³)', fontsize=8, fontname='Times New Roman')

    # Set x-axis major and minor ticks
    plt.gca().xaxis.set_major_locator(plt.MultipleLocator(100))  # Major ticks every 100
    plt.gca().xaxis.set_minor_locator(plt.MultipleLocator(20))   # Minor ticks every 20

    # Set y-axis major and minor ticks
    plt.gca().yaxis.set_major_locator(plt.MultipleLocator(5))    # Major ticks every 5
    plt.gca().yaxis.set_minor_locator(plt.MultipleLocator(1))    # Minor ticks every 1

    # Set tick parameters for both axes - direction set to 'in'
    plt.tick_params(axis='both', which='major', labelsize=8, length=3.5, direction='in')
    plt.tick_params(axis='both', which='minor', labelsize=6, length=2, direction='in')

    # Force y-axis to start from 0 and include 0 in ticks
    min_y = 0
    max_y = max(sizes) * 1.2  # Add 20% margin for labels
    plt.ylim(min_y, max_y)

    # Set font properties for ticks
    plt.xticks(fontsize=8, fontfamily='Times New Roman')
    plt.yticks(fontsize=8, fontfamily='Times New Roman')
    plt.grid(False)

    # Use Times New Roman font for all text
    plt.rcParams['font.family'] = 'Times New Roman'

    # Adjust layout
    plt.tight_layout()

    # Save plot
    save_path = base_path / 'stoOverTA_2' / 'storage_overhead.pdf'
    save_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(save_path, format='pdf', bbox_inches='tight', dpi=300)
    plt.close()

    # Save data to JSON for reference
    data = {
        'vehicle_counts': vehicle_counts,
        'storage_sizes': storage_sizes
    }
    with open(base_path / 'stoOverTA_2' / 'storage_data.json', 'w') as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    test_storage_overhead()
import os
import time
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import authZKP_8
from matplotlib.font_manager import FontProperties


def test_vehicle_authentication(num_vehicles):
    """Test authentication for a given number of vehicles"""
    base_path = r"D:\wp123\Code\python\ZKP-Auth\test_9"
    save_path = os.path.join(base_path, f"test_save_{num_vehicles}")

    proof_gen_times = []
    proof_verify_times = []

    for i in range(num_vehicles):
        try:
            merkle_tree = authZKP_8.MerkleTree(save_path)
            circuit = authZKP_8.Circuit()
            prover = authZKP_8.Prover(save_path)
            verifier = authZKP_8.Verifier()

            merkle_tree.build_tree(
                id_number=f"ID_{i:018d}",
                did=f"did:example:{i:018d}"
            )

            merkle_proof = merkle_tree.get_proof(0)
            if merkle_proof is None:
                continue

            start_time = time.time()
            proof = circuit.generate_proof(
                merkle_proof.leaf,
                merkle_proof.path,
                merkle_proof.root,
                merkle_proof.signature,
                merkle_proof.public_key_pem
            )
            proof_gen_time = time.time() - start_time
            proof_gen_times.append(proof_gen_time)

            if proof is None:
                continue

            session_key, encrypted_key, public_key = prover.generate_session_key()
            encrypted_proof = prover.encrypt_proof(proof, session_key)

            start_time = time.time()
            result = verifier.verify_proof(encrypted_proof, session_key)
            verify_time = time.time() - start_time

            if result == 1:
                proof_verify_times.append(verify_time)

        except Exception as e:
            print(f"Error processing vehicle {i}: {str(e)}")
            continue

    return np.mean(proof_gen_times), np.mean(proof_verify_times)


def run_tests():
    """Run tests for different numbers of vehicles"""
    vehicle_counts = [20, 40, 60, 80, 100]
    gen_times = []
    verify_times = []

    for count in vehicle_counts:
        print(f"\nTesting with {count} vehicles...")
        gen_time, verify_time = test_vehicle_authentication(count)
        gen_times.append(gen_time)
        verify_times.append(verify_time)
        print(f"Average proof generation time: {gen_time:.6f}s")
        print(f"Average proof verification time: {verify_time:.6f}s")

    return vehicle_counts, gen_times, verify_times


def create_visualization(vehicle_counts, gen_times, verify_times, save_path=None):
    """Create and save visualization with exact formatting"""
    # Create figure with specified size
    plt.figure(figsize=(4, 2.5))
    font = FontProperties(family='Times New Roman', size=8)
    fig, ax1 = plt.subplots(figsize=(4, 2.5))
    ax2 = ax1.twinx()

    # Plot generation times
    line1 = ax1.plot(vehicle_counts, gen_times, color='#6CB3DA', marker='o', # #6BAED6
                     label='Proof generation time', markersize=2,
                     markeredgewidth=1.2, markerfacecolor='#7E99F4',
                     linestyle='-', linewidth=1)

    # Plot verification times
    line2 = ax2.plot(vehicle_counts, verify_times, color='#E58760', marker='s', # #FED976
                     label='Proof verification time', markersize=2,
                     markeredgewidth=1.2, markerfacecolor='#925EB0',
                     linestyle='-', linewidth=1)

    # Set y-axis limits and ticks
    ax1.set_ylim(0.98, 1.42)
    ax1.set_yticks(np.arange(1.0, 1.41, 0.1))
    ax2.set_ylim(-0.02, 0.42)
    ax2.set_yticks(np.arange(0.0, 0.41, 0.1))

    # Move ticks inside
    ax1.tick_params(axis='y', direction='in', which='both')
    ax2.tick_params(axis='y', direction='in', which='both')
    ax1.tick_params(axis='x', direction='in', which='both')

    # Add minor ticks
    ax1.minorticks_on()
    ax2.minorticks_on()

    # Labels
    ax1.set_xlabel('Number of vehicles #n', fontproperties=font)
    ax1.set_ylabel('Proof generation time (s)', fontproperties=font)
    ax2.set_ylabel('Proof verification Time (s ×10⁻⁴)', fontproperties=font)

    # Format right y-axis values
    def custom_formatter(x, p):
        return f"{x:.1f}"

    ax2.yaxis.set_major_formatter(plt.FuncFormatter(custom_formatter))

    # Set font size for tick labels
    ax1.tick_params(axis='both', which='major', labelsize=8)
    ax2.tick_params(axis='both', which='major', labelsize=8)

    # Add legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, prop=font, loc='upper left')

    # Remove grid
    ax1.grid(False)
    ax2.grid(False)

    # Adjust layout
    plt.tight_layout()

    # Save plot
    if save_path:
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')

    return plt


def main():
    """Main test function"""
    print("Starting vehicle authentication performance tests...")
    vehicle_counts, gen_times, verify_times = run_tests()

    save_path = r"D:\wp123\Code\python\ZKP-Auth\test_9\performance_results.pdf"
    plot = create_visualization(vehicle_counts, gen_times, verify_times, save_path)
    plt.show()
    plt.close()

    print("\nTests completed. Results have been saved.")


if __name__ == "__main__":
    main()
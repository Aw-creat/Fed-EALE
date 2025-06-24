import numpy as np
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

# Time constants (in milliseconds)
Th = 0.121935    # Time of one-way hash function
Tsm = 0.816450   # Time of scalar multiplication
Tpa = 0.068635   # Time of point addition
Tm = 0.001986    # Time of module addition
Txor = 0.003868  # Time of XOR operation
TSE = 0.018354   # Encryption time of AES
TDE = 0.015878   # Decryption time of AES
Tmod = 0.000263  # Time of mod operation
Ttree = 0.000001 # Time of delete tree

# Calculate times for each scheme
schemes = ['[13]', '[19]', '[20]', '[27]', '[31]', '[32]', 'Ours']

# Proof Generation times (in milliseconds)
proof_gen_times = [
    2*Th + 2*Txor + Tsm,                    # [13]
    3*Th + Tsm + 3*Tm,                      # [19]
    2*Th + Tsm + 2*Tm,                      # [20]
    2*Th + Tsm,                             # [27]
    2*Th + 4*Tsm + 2*Tpa + 3*Tm,           # [31]
    2*Th + 2*Tsm,                                      # [32] (not given)
    1.191077                                # Ours (given)
]

# Proof Verification times (in milliseconds)
proof_ver_times = [
    4*Th + 2*Txor,                          # [13]
    4*Th + 5*Tsm + 4*Tpa,                   # [19]
    3*Th + 2*Tsm + 2*Tpa + Tm,             # [20]
    2*Th + 3*Tsm + 2*Tpa,                  # [27]
    Th + 3*Tsm + 4*Tpa,                    # [31]
    4*Th + 3*Tsm,                          # [32]
    0.695541                               # Ours (given)
]

# Keep times in milliseconds (no conversion needed since input is already in ms)
proof_gen_times = np.array(proof_gen_times)
proof_ver_times = np.array(proof_ver_times)

# Create the visualization
plt.figure(figsize=(4, 2.5))
font = FontProperties(family='Times New Roman', size=8)

x = np.arange(len(schemes))
width = 0.35

fig, ax = plt.subplots(figsize=(4, 2.5))
rects1 = ax.bar(x - width/2, proof_gen_times, width, label='Proof generation time', color='#6BAED6')
rects2 = ax.bar(x + width/2, proof_ver_times, width, label='Verification time', color='#FED976')

# Customize the plot
ax.set_ylabel('Time(ms)', fontproperties=font)
ax.set_xticks(x)
ax.set_xticklabels(schemes, fontproperties=font)
ax.set_xlabel('Scheme', fontproperties=font)
ax.legend(prop=font, loc='upper right')

# Move ticks inside
ax.tick_params(axis='both', direction='in', which='both')
ax.minorticks_on()

# Remove grid
ax.grid(False)

# Set font size for tick labels
ax.tick_params(axis='both', which='major', labelsize=8)

# Adjust layout
plt.tight_layout()

# Save plot
plt.savefig('D:/wp123/Code/python/ZKP-Auth/access/computational.pdf', format='pdf', dpi=300, bbox_inches='tight')

# Display plot
plt.show()

# Print the calculated times
print("\nProof Generation Times (ms):")
for scheme, time in zip(schemes, proof_gen_times):
    print(f"{scheme}: {time:.6f}")

print("\nProof Verification Times (ms):")
for scheme, time in zip(schemes, proof_ver_times):
    print(f"{scheme}: {time:.6f}")
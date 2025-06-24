import numpy as np
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

# Define the data from the table
schemes = ['[13]', '[19]', '[20]', '[27]', '[31]', '[32]', 'Ours']
proof_sizes = [168, 148, 148, 120, 140, 100, 81]
communication_overhead = [284, 440, 156, 184, 224, 196, 90]

# Create the visualization
plt.figure(figsize=(4, 2.5))
font = FontProperties(family='Times New Roman', size=8)

x = np.arange(len(schemes))
width = 0.35

fig, ax = plt.subplots(figsize=(4, 2.5))
rects1 = ax.bar(x - width/2, proof_sizes, width, label='Proof size', color='#ABC8E5')
rects2 = ax.bar(x + width/2, communication_overhead, width, label='Total size', color='#E5A79A')

# Customize the plot
ax.set_ylabel('Communication overhead (bytes)', fontproperties=font)
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
plt.savefig('communication.pdf', format='pdf', dpi=300, bbox_inches='tight')

# Display plot
plt.show()

# Print the values
print("\nProof Sizes (bytes):")
for scheme, size in zip(schemes, proof_sizes):
    print(f"{scheme}: {size}")

print("\nCommunication Overhead (bytes):")
for scheme, overhead in zip(schemes, communication_overhead):
    print(f"{scheme}: {overhead}")
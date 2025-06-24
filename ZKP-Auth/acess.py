import matplotlib.pyplot as plt
import numpy as np
from matplotlib.font_manager import FontProperties
import os

def read_and_process_query_times(file_path):
    """Read and process query times from the file"""
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    query_times = []
    for line in lines:
        if '查询时间' in line:
            time_str = line.split('：')[1].strip()
            # Convert milliseconds to seconds
            time_value = float(time_str.replace('ms', '')) / 1000.0
            query_times.append(time_value)
    return query_times

def analyze_specific_runs(query_times):
    """Analyze average times for specific numbers of runs"""
    runs = [20, 40, 60, 80, 100]  # Added 60 runs
    results = {}
    for n in runs:
        if n <= len(query_times):
            times = query_times[:n]
            avg = np.mean(times)
            results[n] = avg
            print(f"\nAnalysis for {n} runs:")
            print(f"Average time: {avg:.6f} seconds")
            print(f"             {(avg * 1000):.6f} milliseconds")
    return results

def create_visualization(query_times, averages, save_path=None):
    """Create and save visualization with exact formatting"""
    # Create figure with specified size
    plt.figure(figsize=(4, 2.5))
    font = FontProperties(family='Times New Roman', size=8)
    fig, ax = plt.subplots(figsize=(4, 2.5))

    x_values = np.arange(1, len(query_times) + 1)

    # Plot query times with solid markers
    line = ax.plot(x_values, query_times, color='#7E99F4', marker='o',
                   label='Query Time', markersize=2, markeredgewidth=1.2,
                   markerfacecolor='#B2AFDA', linestyle='-', linewidth=1)

    # Add horizontal lines for different averages
    colors = ['#F79059', '#FFBE7A', '#FF69B4', '#E7BDD3', '#9d84bf']  # Added color for 60 runs
    for (n, avg), color in zip(averages.items(), colors):
        ax.axhline(y=avg, color=color, linestyle='--',
                   label=f'Avg ({n} runs)', linewidth=1)

    # Set axis limits and ticks
    ax.set_ylim(0, max(query_times) * 1.1)
    ax.set_xlim(0, len(query_times))

    # Move ticks inside
    ax.tick_params(axis='both', direction='in', which='both')
    ax.minorticks_on()

    # Labels
    ax.set_xlabel('Number of accesses on the blockchain', fontproperties=font)
    ax.set_ylabel('Time (s)', fontproperties=font)

    # Set font size for tick labels
    ax.tick_params(axis='both', which='major', labelsize=8)

    # Add legend
    ax.legend(prop=font, loc='upper right')

    # Remove grid
    ax.grid(False)

    # Adjust layout
    plt.tight_layout()

    # Save plot
    if save_path:
        plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')

    return plt

def main():
    # File paths
    input_file = "D:/wp123/Code/python/ZKP-Auth/access/query.txt"
    output_file = "D:/wp123/Code/python/ZKP-Auth/access/query_time_analysis.pdf"

    # Read and process data
    query_times = read_and_process_query_times(input_file)

    # Analyze specific runs
    averages = analyze_specific_runs(query_times)

    # Create visualization and print results
    plot = create_visualization(query_times, averages, output_file)
    plt.show()
    plt.close()

if __name__ == "__main__":
    main()
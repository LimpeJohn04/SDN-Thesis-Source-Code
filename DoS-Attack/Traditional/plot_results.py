import matplotlib.pyplot as plt
import re

# 1. Configuration
LOG_FILE = 'traditional_server.txt'
OUTPUT_IMAGE = 'bandwidth_graph.png'


def parse_iperf_log(filename):
    """ Reads the log file and returns lists of Time and Bandwidth """
    time_intervals = []
    bandwidths = []
    
    # Regex to match lines like: " 10.0-11.0 sec  817 KBytes  6.70 Mbits/sec"
    # We capture the END time and the Bandwidth
    pattern = re.compile(r"(\d+\.\d+)-(\d+\.\d+)\s+sec.+?(\d+\.\d+)\s+Mbits/sec")

    try:
        with open(filename, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    # group(2) is the end time (e.g., 11.0)
                    # group(3) is the bandwidth (e.g., 6.70)
                    end_time = float(match.group(2))
                    bw_val = float(match.group(3))
                    
                    time_intervals.append(end_time)
                    bandwidths.append(bw_val)
    except FileNotFoundError:
        print(f"Error: Could not find {filename}. Run your experiment first!")
        exit()
        
    return time_intervals, bandwidths

# 2. Get Data
times, bws = parse_iperf_log(LOG_FILE)

# 3. Create Plot
plt.figure(figsize=(15, 6))

# Plot the line
plt.plot(times, bws, marker='o', linestyle='-', color='#007acc', label='UDP Throughput')

# 5. Formatting
plt.title('Network Performance During DoS Attack', fontsize=16)
plt.xlabel('Time (seconds)', fontsize=12)
plt.ylabel('Throughput (Mbps)', fontsize=12)
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.axhline(y=9.5, color='green', linestyle=':', label='Max Capacity (Approx)')
plt.legend()

# 6. Save and Show
print(f"Graph saved to {OUTPUT_IMAGE}")
plt.savefig(OUTPUT_IMAGE)
plt.show()

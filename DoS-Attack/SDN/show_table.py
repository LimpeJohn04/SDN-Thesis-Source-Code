import csv
import sys
import os

def print_table(filename):
    # Check if file exists
    if not os.path.exists(filename):
        print(f"Error: The file '{filename}' was not found.")
        return

    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            data = list(reader)

        if not data:
            print("The CSV file is empty.")
            return

        # Calculate maximum width for each column to ensure perfect alignment
        col_widths = [max(len(str(item)) for item in col) for col in zip(*data)]

        # Define a separator line based on column widths
        separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

        print("\n--- SDN Experiment Results ---")
        print(separator)

        # Print the Header
        header = data[0]
        print("|" + "|".join(f" {item:<{w}} " for item, w in zip(header, col_widths)) + "|")
        print(separator)

        # Print the Data Rows
        for row in data[1:]:
            print("|" + "|".join(f" {item:<{w}} " for item, w in zip(row, col_widths)) + "|")
        
        print(separator + "\n")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Default to your specific file, or take command line argument
    target_file = 'results_sdn.csv'
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        
    print_table(target_file)

#!/usr/bin/env python3
"""
Visualization script for eBPF agent performance data from CSV files.

Usage:
    python3 visualize_ebpf_performance.py <csv_file> <prow_id> [--output <output_file>]

Example:
    python3 visualize_ebpf_performance.py data.csv 1985348508604960768
    python3 visualize_ebpf_performance.py data.csv 1985348508604960768 --output perf.png
"""
import csv
import argparse
import os
import sys
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

def extract_prow_id(build_url):
    """Extract prow ID from build URL."""
    if build_url and '/' in build_url:
        parts = build_url.split('/')
        return parts[-1] if parts else None
    return None

def parse_csv_row(row):
    """Parse a CSV row and extract relevant fields."""
    return {
        'uuid': row[1],
        'nFlowsProcessedTotals_max': float(row[2]) if row[2] else 0,
        'nFlowsProcessedPerMinuteTotals_max': float(row[3]) if row[3] else 0,
        'ebpfFlowsDroppedRatio_avg': float(row[8]) if row[8] else 0,
        'cpuEBPFTotals_avg': float(row[13]) if row[13] else 0,
        'rssEBPFTotals_avg': float(row[18]) if len(row) > 18 and row[18] else 0,  # RSS memory in bytes
        'timestamp': row[34],
        'buildUrl': row[36]
    }

def visualize_csv_data(csv_file, target_prow_id, output_file=None):
    """Create visualizations from CSV data."""
    
    # Read CSV data
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        rows = []
        target_row = None
        target_index = None
        
        for i, row in enumerate(reader):
            if len(row) < 37:
                continue
            
            prow_id = extract_prow_id(row[36])
            parsed_row = parse_csv_row(row)
            parsed_row['prow_id'] = prow_id
            parsed_row['index'] = i
            
            rows.append(parsed_row)
            
            if prow_id == target_prow_id:
                target_row = parsed_row
                target_index = i
    
    if not target_row:
        print(f"Error: Prow ID {target_prow_id} not found in CSV file")
        sys.exit(1)
    
    # Get previous runs
    previous_runs = rows[:target_index]
    all_runs = rows[:target_index + 1]  # Include target
    
    # Create figure with subplots
    fig = plt.figure(figsize=(16, 22))
    gs = fig.add_gridspec(6, 2, hspace=0.3, wspace=0.3)
    
    # Color scheme
    color_prev = '#3498db'  # Blue
    color_current = '#e74c3c'  # Red
    color_avg = '#2ecc71'  # Green
    
    # 1. Flows Processed Over Time
    ax1 = fig.add_subplot(gs[0, 0])
    indices = [r['index'] for r in all_runs]
    flows = [r['nFlowsProcessedTotals_max'] / 1e6 for r in all_runs]
    colors = [color_current if r['prow_id'] == target_prow_id else color_prev for r in all_runs]
    
    ax1.scatter(indices, flows, c=colors, alpha=0.6, s=50)
    if previous_runs:
        avg_flows = sum(r['nFlowsProcessedTotals_max'] for r in previous_runs) / len(previous_runs) / 1e6
        ax1.axhline(y=avg_flows, color=color_avg, linestyle='--', linewidth=2, label=f'Previous Avg: {avg_flows:.2f}M')
    ax1.axhline(y=target_row['nFlowsProcessedTotals_max'] / 1e6, color=color_current, linestyle='--', linewidth=2, alpha=0.5, label=f'Current: {target_row["nFlowsProcessedTotals_max"]/1e6:.2f}M')
    ax1.set_xlabel('Run Index', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Flows Processed (Millions)', fontsize=11, fontweight='bold')
    ax1.set_title('Flows Processed Over Time', fontsize=13, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.legend(fontsize=9)
    
    # 2. Comparison Bar Chart
    ax2 = fig.add_subplot(gs[0, 1])
    if previous_runs:
        prev_avg_flows = sum(r['nFlowsProcessedTotals_max'] for r in previous_runs) / len(previous_runs) / 1e6
        prev_min_flows = min(r['nFlowsProcessedTotals_max'] for r in previous_runs) / 1e6
        prev_max_flows = max(r['nFlowsProcessedTotals_max'] for r in previous_runs) / 1e6
        curr_flows = target_row['nFlowsProcessedTotals_max'] / 1e6
        
        categories = ['Previous\nMin', 'Previous\nAvg', 'Previous\nMax', 'Current\n(Updated)']
        values = [prev_min_flows, prev_avg_flows, prev_max_flows, curr_flows]
        colors_bar = [color_prev, color_prev, color_prev, color_current]
        bars = ax2.bar(categories, values, color=colors_bar, alpha=0.7, edgecolor='black', linewidth=1.5)
        
        # Add value labels on bars
        for bar, val in zip(bars, values):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{val:.2f}M',
                    ha='center', va='bottom', fontweight='bold', fontsize=10)
        
        ax2.set_ylabel('Flows Processed (Millions)', fontsize=11, fontweight='bold')
        ax2.set_title('Flows Processed Comparison', fontsize=13, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='y')
    
    # 3. CPU Usage Comparison
    ax3 = fig.add_subplot(gs[1, 0])
    cpu_values = [r['cpuEBPFTotals_avg'] for r in all_runs]
    colors_cpu = [color_current if r['prow_id'] == target_prow_id else color_prev for r in all_runs]
    
    ax3.scatter(indices, cpu_values, c=colors_cpu, alpha=0.6, s=50)
    if previous_runs:
        avg_cpu = sum(r['cpuEBPFTotals_avg'] for r in previous_runs) / len(previous_runs)
        ax3.axhline(y=avg_cpu, color=color_avg, linestyle='--', linewidth=2, label=f'Previous Avg: {avg_cpu:.3f}')
    ax3.axhline(y=target_row['cpuEBPFTotals_avg'], color=color_current, linestyle='--', linewidth=2, alpha=0.5, label=f'Current: {target_row["cpuEBPFTotals_avg"]:.3f}')
    ax3.set_xlabel('Run Index', fontsize=11, fontweight='bold')
    ax3.set_ylabel('CPU Usage (cores)', fontsize=11, fontweight='bold')
    ax3.set_title('eBPF CPU Usage Over Time', fontsize=13, fontweight='bold')
    ax3.grid(True, alpha=0.3)
    ax3.legend(fontsize=9)
    
    # 4. Memory Usage Over Time
    ax4 = fig.add_subplot(gs[1, 1])
    mem_values = [r['rssEBPFTotals_avg'] / 1e9 for r in all_runs]  # Convert to GB
    colors_mem = [color_current if r['prow_id'] == target_prow_id else color_prev for r in all_runs]
    
    ax4.scatter(indices, mem_values, c=colors_mem, alpha=0.6, s=50)
    if previous_runs:
        avg_mem = sum(r['rssEBPFTotals_avg'] for r in previous_runs) / len(previous_runs) / 1e9
        ax4.axhline(y=avg_mem, color=color_avg, linestyle='--', linewidth=2, label=f'Previous Avg: {avg_mem:.2f} GB')
    ax4.axhline(y=target_row['rssEBPFTotals_avg'] / 1e9, color=color_current, linestyle='--', linewidth=2, alpha=0.5, label=f'Current: {target_row["rssEBPFTotals_avg"]/1e9:.2f} GB')
    ax4.set_xlabel('Run Index', fontsize=11, fontweight='bold')
    ax4.set_ylabel('Memory Usage RSS (GB)', fontsize=11, fontweight='bold')
    ax4.set_title('eBPF Memory Usage Over Time', fontsize=13, fontweight='bold')
    ax4.grid(True, alpha=0.3)
    ax4.legend(fontsize=9)
    
    # 5. CPU vs Flows Per Minute Efficiency
    ax5 = fig.add_subplot(gs[2, 0])
    if previous_runs:
        prev_cpu = [r['cpuEBPFTotals_avg'] for r in previous_runs]
        prev_flows_per_min = [r['nFlowsProcessedPerMinuteTotals_max'] / 1e6 for r in previous_runs]
        curr_cpu = target_row['cpuEBPFTotals_avg']
        curr_flows_per_min = target_row['nFlowsProcessedPerMinuteTotals_max'] / 1e6
        
        ax5.scatter(prev_flows_per_min, prev_cpu, c=color_prev, alpha=0.6, s=50, label='Previous Runs')
        ax5.scatter(curr_flows_per_min, curr_cpu, c=color_current, s=200, marker='*', 
                   edgecolor='black', linewidth=2, label='Current (Updated)', zorder=5)
        
        # Add efficiency line (flows per minute per core)
        if prev_flows_per_min:
            x_range = np.linspace(min(prev_flows_per_min), max(max(prev_flows_per_min), curr_flows_per_min), 100)
            # Calculate average efficiency using flows per minute
            efficiencies = [f / c for f, c in zip(prev_flows_per_min, prev_cpu)]
            avg_efficiency = sum(efficiencies) / len(efficiencies)
            y_line = x_range / avg_efficiency
            ax5.plot(x_range, y_line, '--', color='gray', alpha=0.5, linewidth=1, 
                    label=f'Avg Efficiency: {avg_efficiency:.1f}M flows/min/core')
        
        ax5.set_xlabel('Flows Per Minute (Millions)', fontsize=11, fontweight='bold')
        ax5.set_ylabel('CPU Usage (cores)', fontsize=11, fontweight='bold')
        ax5.set_title('CPU Efficiency (Flows/Min per Core)', fontsize=13, fontweight='bold')
        ax5.grid(True, alpha=0.3)
        ax5.legend(fontsize=9)
    
    # 6. Memory vs Flows Per Minute Efficiency
    ax6 = fig.add_subplot(gs[2, 1])
    if previous_runs:
        prev_mem = [r['rssEBPFTotals_avg'] / 1e6 for r in previous_runs]  # Convert to MB
        prev_flows_per_min = [r['nFlowsProcessedPerMinuteTotals_max'] / 1e6 for r in previous_runs]
        curr_mem = target_row['rssEBPFTotals_avg'] / 1e6  # Convert to MB
        curr_flows_per_min = target_row['nFlowsProcessedPerMinuteTotals_max'] / 1e6
        
        ax6.scatter(prev_flows_per_min, prev_mem, c=color_prev, alpha=0.6, s=50, label='Previous Runs')
        ax6.scatter(curr_flows_per_min, curr_mem, c=color_current, s=200, marker='*', 
                   edgecolor='black', linewidth=2, label='Current (Updated)', zorder=5)
        
        # Add efficiency line (flows per minute per MB)
        if prev_flows_per_min:
            x_range = np.linspace(min(prev_flows_per_min), max(max(prev_flows_per_min), curr_flows_per_min), 100)
            # Calculate average efficiency using flows per minute per MB
            efficiencies = [f / m for f, m in zip(prev_flows_per_min, prev_mem)]
            avg_efficiency = sum(efficiencies) / len(efficiencies)
            y_line = x_range / avg_efficiency
            ax6.plot(x_range, y_line, '--', color='gray', alpha=0.5, linewidth=1, 
                    label=f'Avg Efficiency: {avg_efficiency:.2f}M flows/min/MB')
        
        ax6.set_xlabel('Flows Per Minute (Millions)', fontsize=11, fontweight='bold')
        ax6.set_ylabel('Memory Usage RSS (MB)', fontsize=11, fontweight='bold')
        ax6.set_title('Memory Efficiency (Flows/Min per MB)', fontsize=13, fontweight='bold')
        ax6.grid(True, alpha=0.3)
        ax6.legend(fontsize=9)
    
    # 7. Efficiency Comparison (Percentage) - Full width
    ax7 = fig.add_subplot(gs[3, :])
    if previous_runs:
        prev_avg_flows_per_min = sum(r['nFlowsProcessedPerMinuteTotals_max'] for r in previous_runs) / len(previous_runs)
        prev_avg_cpu = sum(r['cpuEBPFTotals_avg'] for r in previous_runs) / len(previous_runs)
        prev_avg_mem = sum(r['rssEBPFTotals_avg'] for r in previous_runs if r['rssEBPFTotals_avg'] > 0) / max(1, len([r for r in previous_runs if r['rssEBPFTotals_avg'] > 0]))
        
        curr_flows_per_min = target_row['nFlowsProcessedPerMinuteTotals_max']
        curr_cpu = target_row['cpuEBPFTotals_avg']
        curr_mem = target_row['rssEBPFTotals_avg']
        
        # Calculate efficiencies using flows per minute (rate-based)
        prev_cpu_eff = prev_avg_flows_per_min / prev_avg_cpu / 1e6 if prev_avg_cpu > 0 else 0  # M flows/min per core
        curr_cpu_eff = curr_flows_per_min / curr_cpu / 1e6 if curr_cpu > 0 else 0
        prev_mem_eff = prev_avg_flows_per_min / (prev_avg_mem / 1e6) / 1e6 if prev_avg_mem > 0 else 0  # M flows/min per MB
        curr_mem_eff = curr_flows_per_min / (curr_mem / 1e6) / 1e6 if curr_mem > 0 else 0
        
        # Calculate percentage changes
        cpu_eff_change = ((curr_cpu_eff - prev_cpu_eff) / prev_cpu_eff * 100) if prev_cpu_eff > 0 else 0
        mem_eff_change = ((curr_mem_eff - prev_mem_eff) / prev_mem_eff * 100) if prev_mem_eff > 0 else 0
        
        # Create efficiency percentage change bar chart
        categories = ['CPU Efficiency\n(flows/min/core)', 'Memory Efficiency\n(flows/min/MB)']
        changes = [cpu_eff_change, mem_eff_change]
        colors_change = [color_avg if c >= 0 else '#e67e22' for c in changes]  # Green for improvement, orange for regression
        
        x = np.arange(len(categories))
        width = 0.6  # Wider bars for better visibility in full-width plot
        bars = ax7.bar(x, changes, width, color=colors_change, alpha=0.7, edgecolor='black', linewidth=1.5)
        
        # Add value labels on bars
        for bar, change in zip(bars, changes):
            height = bar.get_height()
            # Center text within the bar (middle of the bar height)
            # For negative bars, height is negative, so text_y will be negative too (which is correct)
            text_y = height / 2
            # Use white text for better contrast on colored bars
            text_color = 'white' if abs(height) > 1 else 'black'
            # Show percentage change prominently
            ax7.text(bar.get_x() + bar.get_width()/2., text_y,
                    f'{change:+.2f}%',
                    ha='center', va='center',
                    fontweight='bold', fontsize=12, color=text_color)
        
        # Add zero line
        ax7.axhline(y=0, color='black', linestyle='-', linewidth=1)
        ax7.set_ylabel('Efficiency Change (%)', fontsize=11, fontweight='bold')
        ax7.set_title('Efficiency Change vs Previous Average', fontsize=13, fontweight='bold')
        ax7.set_xticks(x)
        ax7.set_xticklabels(categories, fontsize=10)
        ax7.grid(True, alpha=0.3, axis='y')
        
        # Add legend for colors
        legend_elements = [
            mpatches.Patch(facecolor=color_avg, alpha=0.7, label='Improvement'),
            mpatches.Patch(facecolor='#e67e22', alpha=0.7, label='Regression')
        ]
        ax7.legend(handles=legend_elements, fontsize=9, loc='upper right')
    
    # 8. Summary Statistics - 3 columns
    # Create a sub-gridspec for row 4 to split into 3 columns
    summary_gs = gs[4, :].subgridspec(1, 3, wspace=0.2)
    
    ax8 = fig.add_subplot(summary_gs[0, 0])
    ax8.axis('off')
    
    ax9 = fig.add_subplot(summary_gs[0, 1])
    ax9.axis('off')
    
    ax10 = fig.add_subplot(summary_gs[0, 2])
    ax10.axis('off')
    
    if previous_runs:
        prev_avg_flows = sum(r['nFlowsProcessedTotals_max'] for r in previous_runs) / len(previous_runs)
        prev_avg_flows_per_min = sum(r['nFlowsProcessedPerMinuteTotals_max'] for r in previous_runs) / len(previous_runs)
        prev_avg_cpu = sum(r['cpuEBPFTotals_avg'] for r in previous_runs) / len(previous_runs)
        prev_avg_mem = sum(r['rssEBPFTotals_avg'] for r in previous_runs if r['rssEBPFTotals_avg'] > 0) / max(1, len([r for r in previous_runs if r['rssEBPFTotals_avg'] > 0]))
        prev_avg_dropped = sum(r['ebpfFlowsDroppedRatio_avg'] for r in previous_runs) / len(previous_runs)
        
        curr_flows = target_row['nFlowsProcessedTotals_max']
        curr_flows_per_min = target_row['nFlowsProcessedPerMinuteTotals_max']
        curr_cpu = target_row['cpuEBPFTotals_avg']
        curr_mem = target_row['rssEBPFTotals_avg']
        curr_dropped = target_row['ebpfFlowsDroppedRatio_avg']
        
        flows_change = ((curr_flows - prev_avg_flows) / prev_avg_flows * 100) if prev_avg_flows > 0 else 0
        flows_per_min_change = ((curr_flows_per_min - prev_avg_flows_per_min) / prev_avg_flows_per_min * 100) if prev_avg_flows_per_min > 0 else 0
        cpu_change = ((curr_cpu - prev_avg_cpu) / prev_avg_cpu * 100) if prev_avg_cpu > 0 else 0
        mem_change = ((curr_mem - prev_avg_mem) / prev_avg_mem * 100) if prev_avg_mem > 0 else 0
        dropped_change = ((curr_dropped - prev_avg_dropped) / prev_avg_dropped * 100) if prev_avg_dropped > 0 else (0 if curr_dropped == 0 else float('inf'))
        
        # Calculate efficiencies for summary
        prev_cpu_eff = prev_avg_flows_per_min / prev_avg_cpu / 1e6 if prev_avg_cpu > 0 else 0
        curr_cpu_eff = curr_flows_per_min / curr_cpu / 1e6 if curr_cpu > 0 else 0
        prev_mem_eff = prev_avg_flows_per_min / (prev_avg_mem / 1e6) / 1e6 if prev_avg_mem > 0 else 0  # M flows/min per MB
        curr_mem_eff = curr_flows_per_min / (curr_mem / 1e6) / 1e6 if curr_mem > 0 else 0
        
        cpu_eff_change = ((curr_cpu_eff - prev_cpu_eff) / prev_cpu_eff * 100) if prev_cpu_eff > 0 else 0
        mem_eff_change = ((curr_mem_eff - prev_mem_eff) / prev_mem_eff * 100) if prev_mem_eff > 0 else 0
        
        # Determine dropped flows status
        if curr_dropped == 0 and prev_avg_dropped == 0:
            dropped_status = '[OK] Zero drops'
        elif curr_dropped == 0 and prev_avg_dropped > 0:
            dropped_status = '[OK] Eliminated drops'
        elif curr_dropped > 0:
            dropped_status = '[WARN] Drops present'
        else:
            dropped_status = '[OK] No change'
        
        # Format dropped change
        if dropped_change == float('inf'):
            dropped_change_str = 'N/A'
        else:
            dropped_change_str = f'{dropped_change:+.2f}%'
        
        summary_col1 = f"""
PERFORMANCE SUMMARY

Target Prow ID: {target_prow_id}
Previous Runs: {len(previous_runs)}

FLOWS PROCESSED
  Previous Avg: {prev_avg_flows/1e6:.2f}M flows
  Current:      {curr_flows/1e6:.2f}M flows
  Change:       {flows_change:+.2f}%

FLOWS PER MINUTE
  Previous Avg: {prev_avg_flows_per_min/1e6:.2f}M flows/min
  Current:      {curr_flows_per_min/1e6:.2f}M flows/min
  Change:       {flows_per_min_change:+.2f}%
        """
        
        summary_col2 = f"""
RESOURCE USAGE

CPU USAGE
  Previous Avg: {prev_avg_cpu:.3f} cores
  Current:      {curr_cpu:.3f} cores
  Change:       {cpu_change:+.2f}%

MEMORY (RSS)
  Previous Avg: {prev_avg_mem/1e9:.2f} GB
  Current:      {curr_mem/1e9:.2f} GB
  Change:       {mem_change:+.2f}%
        """
        
        summary_col3 = f"""
EFFICIENCY (Rate-Based)

CPU Efficiency:
  Previous:   {prev_cpu_eff:.2f}M flows/min/core
  Current:    {curr_cpu_eff:.2f}M flows/min/core
  Change:     {cpu_eff_change:+.2f}%

Memory Efficiency:
  Previous:   {prev_mem_eff:.2f}M flows/min/MB
  Current:    {curr_mem_eff:.2f}M flows/min/MB
  Change:     {mem_eff_change:+.2f}%
        """
        
        ax8.text(0.05, 0.5, summary_col1, fontsize=10, family='monospace',
                verticalalignment='center', horizontalalignment='left',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        ax9.text(0.05, 0.5, summary_col2, fontsize=10, family='monospace',
                verticalalignment='center', horizontalalignment='left',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        ax10.text(0.05, 0.5, summary_col3, fontsize=10, family='monospace',
                verticalalignment='center', horizontalalignment='left',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    # 9. Dropped Flows - Separate text box
    ax11 = fig.add_subplot(gs[5, :])  # Full width
    ax11.axis('off')
    
    if previous_runs:
        dropped_flows_text = f"""
DROPPED FLOWS (Ratio)
  Previous Avg: {prev_avg_dropped:.6f}
  Current:      {curr_dropped:.6f}
  Change:       {dropped_change_str}
  Status:       {dropped_status}
        """
        
        ax11.text(0.5, 0.5, dropped_flows_text, fontsize=10, family='monospace',
                verticalalignment='center', horizontalalignment='center',
                bbox=dict(boxstyle='round', facecolor='lightgreen' if dropped_status.startswith('[OK]') else 'lightyellow', alpha=0.8))
    
    # Main title
    fig.suptitle('eBPF Agent Performance Analysis\n(Updated Code vs Previous Runs)', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Determine output file
    if output_file is None:
        # Create perf directory if it doesn't exist
        perf_dir = 'perf'
        os.makedirs(perf_dir, exist_ok=True)
        output_file = os.path.join(perf_dir, 'ebpf_performance_visualization.png')
    else:
        # If output is specified, ensure directory exists
        output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else '.'
        if output_dir and output_dir != '.':
            os.makedirs(output_dir, exist_ok=True)
    
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"[OK] Visualization saved to: {output_file}")
    return output_file

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Visualize eBPF agent performance data from CSV file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s data.csv 1985348508604960768
  %(prog)s data.csv 1985348508604960768 --output perf.png
        """
    )
    parser.add_argument('csv_file', help='Path to CSV file with performance data')
    parser.add_argument('prow_id', help='Prow ID of the target run to compare')
    parser.add_argument('--output', '-o', help='Output PNG file path (default: perf/ebpf_performance_visualization.png)')
    
    args = parser.parse_args()
    
    # Check if CSV file exists
    if not os.path.exists(args.csv_file):
        print(f"Error: CSV file not found: {args.csv_file}")
        sys.exit(1)
    
    print(f"Creating visualization from {args.csv_file}")
    print(f"Target Prow ID: {args.prow_id}")
    
    visualize_csv_data(args.csv_file, args.prow_id, args.output)
    print("\n[OK] Visualization completed successfully!")

if __name__ == '__main__':
    main()


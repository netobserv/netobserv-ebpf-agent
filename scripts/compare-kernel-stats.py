#!/usr/bin/env python3
"""
Compare kernel stats from two benchmark runs and generate matplotlib visualizations.

Usage:
    python3 compare-kernel-stats.py --baseline <file1.json> --comparison <file2.json> --output <report.png>
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import numpy as np


def load_stats(filepath):
    """Load kernel stats from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def calculate_percentage_change(old_val, new_val):
    """Calculate percentage change between two values."""
    if old_val == 0:
        if new_val == 0:
            return 0.0
        return float('inf') if new_val > 0 else float('-inf')
    return ((new_val - old_val) / old_val) * 100


def generate_matplotlib_report(baseline_stats, comparison_stats, baseline_label, comparison_label, output_file,
                                baseline_packet_stats=None, comparison_packet_stats=None, cluster_info=None):
    """Generate matplotlib visualization report as separate graph files."""
    
    baseline_programs = baseline_stats.get('program_stats', {})
    comparison_programs = comparison_stats.get('program_stats', {})
    
    # Collect all program names (only those with activity)
    all_programs = []
    for prog_name in sorted(set(baseline_programs.keys()) | set(comparison_programs.keys())):
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        # Only include programs with activity in at least one run
        if (baseline_prog.get('events_per_sec', 0) > 0 or 
            comparison_prog.get('events_per_sec', 0) > 0 or
            baseline_prog.get('estimated_cpu_percent', 0) > 0 or
            comparison_prog.get('estimated_cpu_percent', 0) > 0):
            all_programs.append(prog_name or '(unnamed)')
    
    # Calculate totals
    baseline_total_cpu = baseline_stats.get('total_estimated_cpu_percent', 0)
    comparison_total_cpu = comparison_stats.get('total_estimated_cpu_percent', 0)
    cpu_change = calculate_percentage_change(baseline_total_cpu, comparison_total_cpu)
    
    baseline_total_events = baseline_stats.get('total_events_per_sec', 0)
    comparison_total_events = comparison_stats.get('total_events_per_sec', 0)
    events_change = calculate_percentage_change(baseline_total_events, comparison_total_events)
    
    baseline_total_runtime = baseline_stats.get('total_runtime_ns', 0)
    comparison_total_runtime = comparison_stats.get('total_runtime_ns', 0)
    
    # Calculate average runtime per event (total runtime / total run count)
    baseline_run_count = baseline_stats.get('total_run_count', 0)
    comparison_run_count = comparison_stats.get('total_run_count', 0)
    
    baseline_avg_runtime = baseline_total_runtime / baseline_run_count if baseline_run_count > 0 else 0
    comparison_avg_runtime = comparison_total_runtime / comparison_run_count if comparison_run_count > 0 else 0
    avg_runtime_change = calculate_percentage_change(baseline_avg_runtime, comparison_avg_runtime)
    
    # Collection duration is stored in nanoseconds - handle both old and new field names
    duration_ns = baseline_stats.get('collection_duration_ns') or baseline_stats.get('collection_duration_sec', 0)
    duration_sec = duration_ns / 1e9
    
    # Load and process packet stats if available
    baseline_packets_per_sec = 0
    baseline_flows_per_sec = 0
    baseline_bytes_per_sec = 0
    comparison_packets_per_sec = 0
    comparison_flows_per_sec = 0
    comparison_bytes_per_sec = 0
    
    if baseline_packet_stats:
        baseline_packets_per_sec = baseline_packet_stats.get('avg_packets_per_sec', 0)
        baseline_flows_per_sec = baseline_packet_stats.get('avg_flows_per_sec', 0)
        baseline_bytes_per_sec = baseline_packet_stats.get('avg_bytes_per_sec', 0)
    
    if comparison_packet_stats:
        comparison_packets_per_sec = comparison_packet_stats.get('avg_packets_per_sec', 0)
        comparison_flows_per_sec = comparison_packet_stats.get('avg_flows_per_sec', 0)
        comparison_bytes_per_sec = comparison_packet_stats.get('avg_bytes_per_sec', 0)
    
    # Calculate efficiency metrics
    # CPU efficiency: packets per second per CPU percent
    baseline_cpu_efficiency_packets = baseline_packets_per_sec / baseline_total_cpu if baseline_total_cpu > 0 else 0
    comparison_cpu_efficiency_packets = comparison_packets_per_sec / comparison_total_cpu if comparison_total_cpu > 0 else 0
    cpu_efficiency_packets_change = calculate_percentage_change(baseline_cpu_efficiency_packets, comparison_cpu_efficiency_packets)
    
    # CPU efficiency: flows per second per CPU percent
    baseline_cpu_efficiency_flows = baseline_flows_per_sec / baseline_total_cpu if baseline_total_cpu > 0 else 0
    comparison_cpu_efficiency_flows = comparison_flows_per_sec / comparison_total_cpu if comparison_total_cpu > 0 else 0
    cpu_efficiency_flows_change = calculate_percentage_change(baseline_cpu_efficiency_flows, comparison_cpu_efficiency_flows)
    
    # CPU efficiency: bytes per second per CPU percent
    baseline_cpu_efficiency_bytes = baseline_bytes_per_sec / baseline_total_cpu if baseline_total_cpu > 0 else 0
    comparison_cpu_efficiency_bytes = comparison_bytes_per_sec / comparison_total_cpu if comparison_total_cpu > 0 else 0
    cpu_efficiency_bytes_change = calculate_percentage_change(baseline_cpu_efficiency_bytes, comparison_cpu_efficiency_bytes)
    
    # Events efficiency: packets per event
    baseline_events_efficiency_packets = baseline_packets_per_sec / baseline_total_events if baseline_total_events > 0 else 0
    comparison_events_efficiency_packets = comparison_packets_per_sec / comparison_total_events if comparison_total_events > 0 else 0
    events_efficiency_packets_change = calculate_percentage_change(baseline_events_efficiency_packets, comparison_events_efficiency_packets)
    
    # Packets/Flows/Bytes changes
    packets_change = calculate_percentage_change(baseline_packets_per_sec, comparison_packets_per_sec)
    flows_change = calculate_percentage_change(baseline_flows_per_sec, comparison_flows_per_sec)
    bytes_change = calculate_percentage_change(baseline_bytes_per_sec, comparison_bytes_per_sec)
    
    # Calculate program metadata totals
    baseline_total_memlock = 0
    baseline_total_jited_size = 0
    baseline_total_verified_insns = 0
    baseline_total_maps = 0
    comparison_total_memlock = 0
    comparison_total_jited_size = 0
    comparison_total_verified_insns = 0
    comparison_total_maps = 0
    
    for prog_name in all_programs:
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        baseline_total_memlock += baseline_prog.get('memlock_bytes', 0)
        baseline_total_jited_size += baseline_prog.get('jited_size_bytes', 0)
        baseline_total_verified_insns += baseline_prog.get('verified_instructions', 0)
        baseline_total_maps += baseline_prog.get('num_maps', 0)
        comparison_total_memlock += comparison_prog.get('memlock_bytes', 0)
        comparison_total_jited_size += comparison_prog.get('jited_size_bytes', 0)
        comparison_total_verified_insns += comparison_prog.get('verified_instructions', 0)
        comparison_total_maps += comparison_prog.get('num_maps', 0)
    
    memlock_change = calculate_percentage_change(baseline_total_memlock, comparison_total_memlock)
    jited_size_change = calculate_percentage_change(baseline_total_jited_size, comparison_total_jited_size)
    verified_insns_change = calculate_percentage_change(baseline_total_verified_insns, comparison_total_verified_insns)
    maps_change = calculate_percentage_change(baseline_total_maps, comparison_total_maps)
    
    # Extract base path from output_file to create separate graph files
    output_path = Path(output_file)
    base_dir = output_path.parent
    base_name = output_path.stem  # filename without extension
    
    # Set style
    plt.style.use('default')
    
    generated_files = []
    
    # Helper function to save a figure
    def save_figure(fig, filename, title):
        """Save a figure to a file with title."""
        fig.suptitle(title, fontsize=14, fontweight='bold')
        fig.text(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 
                 ha='right', va='bottom', fontsize=8, style='italic')
        filepath = base_dir / filename
        fig.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close(fig)
        generated_files.append(filepath)
        print(f"Graph generated: {filepath}")
    
    # Store plot data for combined figure
    plot_data = []
    
    # 1. CPU Usage Comparison (by program)
    fig1 = plt.figure(figsize=(14, 8))
    ax1 = fig1.add_subplot(1, 1, 1)
    baseline_cpus = []
    comparison_cpus = []
    program_labels = []
    
    for prog_name in all_programs:
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        baseline_cpu = baseline_prog.get('estimated_cpu_percent', 0)
        comparison_cpu = comparison_prog.get('estimated_cpu_percent', 0)
        
        if baseline_cpu > 0 or comparison_cpu > 0:
            baseline_cpus.append(baseline_cpu)
            comparison_cpus.append(comparison_cpu)
            # Truncate long program names
            label = prog_name[:20] + '...' if len(prog_name) > 20 else prog_name
            program_labels.append(label)
    
    if baseline_cpus:
        x = np.arange(len(program_labels))
        width = 0.35
        
        bars1 = ax1.bar(x - width/2, baseline_cpus, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax1.bar(x + width/2, comparison_cpus, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        ax1.set_xlabel('Program', fontweight='bold')
        ax1.set_ylabel('CPU Usage (%)', fontweight='bold')
        ax1.set_title('CPU Usage by Program', fontweight='bold', fontsize=12)
        ax1.set_xticks(x)
        ax1.set_xticklabels(program_labels, rotation=45, ha='right', fontsize=8)
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')
        ax1.set_yscale('log')
        
        save_figure(fig1, f'{base_name}-cpu-usage.png', 
                    f'CPU Usage by Program\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    else:
        plt.close(fig1)
    
    # 2. Events/sec Comparison (by program)
    fig2 = plt.figure(figsize=(14, 8))
    ax2 = fig2.add_subplot(1, 1, 1)
    baseline_events = []
    comparison_events = []
    program_labels2 = []
    
    for prog_name in all_programs:
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        baseline_evt = baseline_prog.get('events_per_sec', 0)
        comparison_evt = comparison_prog.get('events_per_sec', 0)
        
        if baseline_evt > 0 or comparison_evt > 0:
            baseline_events.append(baseline_evt)
            comparison_events.append(comparison_evt)
            label = prog_name[:20] + '...' if len(prog_name) > 20 else prog_name
            program_labels2.append(label)
    
    if baseline_events:
        x = np.arange(len(program_labels2))
        width = 0.35
        
        bars1 = ax2.bar(x - width/2, baseline_events, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax2.bar(x + width/2, comparison_events, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        ax2.set_xlabel('Program', fontweight='bold')
        ax2.set_ylabel('Events/sec', fontweight='bold')
        ax2.set_title('Events/sec by Program', fontweight='bold', fontsize=12)
        ax2.set_xticks(x)
        ax2.set_xticklabels(program_labels2, rotation=45, ha='right', fontsize=8)
        ax2.legend()
        ax2.grid(True, alpha=0.3, axis='y')
        ax2.set_yscale('log')
        
        save_figure(fig2, f'{base_name}-events-per-sec.png', 
                    f'Events/sec by Program\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    else:
        plt.close(fig2)
    
    # 3a. CPU Usage Comparison
    fig3a = plt.figure(figsize=(8, 6))
    ax3a = fig3a.add_subplot(1, 1, 1)
    metrics_cpu = ['CPU %']
    baseline_values_cpu = [baseline_total_cpu]
    comparison_values_cpu = [comparison_total_cpu]
    
    x = np.arange(len(metrics_cpu))
    width = 0.35
    
    bars1 = ax3a.bar(x - width/2, baseline_values_cpu, width, label=baseline_label, color='#3498db', alpha=0.8)
    bars2 = ax3a.bar(x + width/2, comparison_values_cpu, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    
    # Add percentage change label
    max_val = max(baseline_total_cpu, comparison_total_cpu) if max(baseline_total_cpu, comparison_total_cpu) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(cpu_change) < 1 else ('green' if cpu_change < 0 else 'red')
    ax3a.text(0, y_pos, f'{cpu_change:+.2f}%', ha='center', va='bottom', 
            fontsize=10, fontweight='bold', color=color)
    
    ax3a.set_ylabel('CPU Usage (%)', fontweight='bold')
    ax3a.set_title('Total CPU Usage Comparison', fontweight='bold', fontsize=12)
    ax3a.set_xticks(x)
    ax3a.set_xticklabels(metrics_cpu)
    ax3a.legend()
    ax3a.grid(True, alpha=0.3, axis='y')
    
    save_figure(fig3a, f'{base_name}-cpu-total.png', 
                f'Total CPU Usage Comparison\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    
    # 3b. Events/sec Comparison
    fig3b = plt.figure(figsize=(8, 6))
    ax3b = fig3b.add_subplot(1, 1, 1)
    metrics_events = ['Events/s']
    baseline_values_events = [baseline_total_events]
    comparison_values_events = [comparison_total_events]
    
    x = np.arange(len(metrics_events))
    width = 0.35
    
    bars1 = ax3b.bar(x - width/2, baseline_values_events, width, label=baseline_label, color='#3498db', alpha=0.8)
    bars2 = ax3b.bar(x + width/2, comparison_values_events, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    
    # Add percentage change label
    max_val = max(baseline_total_events, comparison_total_events) if max(baseline_total_events, comparison_total_events) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(events_change) < 1 else ('green' if events_change > 0 else 'red')
    ax3b.text(0, y_pos, f'{events_change:+.2f}%', ha='center', va='bottom', 
            fontsize=10, fontweight='bold', color=color)
    
    ax3b.set_ylabel('Events/sec', fontweight='bold')
    ax3b.set_title('Total Events/sec Comparison', fontweight='bold', fontsize=12)
    ax3b.set_xticks(x)
    ax3b.set_xticklabels(metrics_events)
    ax3b.legend()
    ax3b.grid(True, alpha=0.3, axis='y')
    
    save_figure(fig3b, f'{base_name}-events-total.png', 
                f'Total Events/sec Comparison\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    
    # 3c. Average Runtime Comparison
    fig3c = plt.figure(figsize=(8, 6))
    ax3c = fig3c.add_subplot(1, 1, 1)
    metrics_runtime = ['Avg Runtime (μs)']
    baseline_values_runtime = [baseline_avg_runtime / 1e3]  # Convert to microseconds
    comparison_values_runtime = [comparison_avg_runtime / 1e3]
    
    x = np.arange(len(metrics_runtime))
    width = 0.35
    
    bars1 = ax3c.bar(x - width/2, baseline_values_runtime, width, label=baseline_label, color='#3498db', alpha=0.8)
    bars2 = ax3c.bar(x + width/2, comparison_values_runtime, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    
    # Add percentage change label
    max_val = max(baseline_values_runtime[0], comparison_values_runtime[0]) if max(baseline_values_runtime[0], comparison_values_runtime[0]) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(avg_runtime_change) < 1 else ('green' if avg_runtime_change < 0 else 'red')
    ax3c.text(0, y_pos, f'{avg_runtime_change:+.2f}%', ha='center', va='bottom', 
            fontsize=10, fontweight='bold', color=color)
    
    ax3c.set_ylabel('Average Runtime (μs)', fontweight='bold')
    ax3c.set_title('Average Runtime per Event Comparison', fontweight='bold', fontsize=12)
    ax3c.set_xticks(x)
    ax3c.set_xticklabels(metrics_runtime)
    ax3c.legend()
    ax3c.grid(True, alpha=0.3, axis='y')
    
    save_figure(fig3c, f'{base_name}-avg-runtime-total.png', 
                f'Average Runtime per Event Comparison\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    
    # 4. Average Runtime Comparison (by program)
    fig4 = plt.figure(figsize=(14, 8))
    ax4 = fig4.add_subplot(1, 1, 1)
    baseline_runtimes = []
    comparison_runtimes = []
    program_labels3 = []
    
    for prog_name in all_programs:
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        baseline_rt = baseline_prog.get('avg_runtime_ns', 0) / 1e3  # Convert to microseconds
        comparison_rt = comparison_prog.get('avg_runtime_ns', 0) / 1e3
        
        if baseline_rt > 0 or comparison_rt > 0:
            baseline_runtimes.append(baseline_rt)
            comparison_runtimes.append(comparison_rt)
            label = prog_name[:20] + '...' if len(prog_name) > 20 else prog_name
            program_labels3.append(label)
    
    if baseline_runtimes:
        x = np.arange(len(program_labels3))
        width = 0.35
        
        bars1 = ax4.bar(x - width/2, baseline_runtimes, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax4.bar(x + width/2, comparison_runtimes, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        ax4.set_xlabel('Program', fontweight='bold')
        ax4.set_ylabel('Avg Runtime (μs)', fontweight='bold')
        ax4.set_title('Average Runtime by Program', fontweight='bold', fontsize=12)
        ax4.set_xticks(x)
        ax4.set_xticklabels(program_labels3, rotation=45, ha='right', fontsize=8)
        ax4.legend()
        ax4.grid(True, alpha=0.3, axis='y')
        ax4.set_yscale('log')
        
        save_figure(fig4, f'{base_name}-avg-runtime.png', 
                    f'Average Runtime by Program\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    else:
        plt.close(fig4)
    
    # 5. Packet Stats Comparison (if available)
    if baseline_packet_stats or comparison_packet_stats:
        fig5 = plt.figure(figsize=(10, 6))
        ax5 = fig5.add_subplot(1, 1, 1)
        packet_metrics = ['Packets/s', 'Flows/s', 'Bytes/s (MB)']
        baseline_packet_values = [
            baseline_packets_per_sec,
            baseline_flows_per_sec,
            baseline_bytes_per_sec / 1e6  # Convert to MB/s
        ]
        comparison_packet_values = [
            comparison_packets_per_sec,
            comparison_flows_per_sec,
            comparison_bytes_per_sec / 1e6  # Convert to MB/s
        ]
        
        x = np.arange(len(packet_metrics))
        width = 0.35
        
        bars1 = ax5.bar(x - width/2, baseline_packet_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax5.bar(x + width/2, comparison_packet_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        # Add percentage change labels
        packet_changes = [packets_change, flows_change, bytes_change]
        for i, (base, comp, change) in enumerate(zip(baseline_packet_values, comparison_packet_values, packet_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change > 0 else 'red')
            ax5.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', 
                    fontsize=9, fontweight='bold', color=color)
        
        ax5.set_xlabel('Metric', fontweight='bold')
        ax5.set_ylabel('Rate', fontweight='bold')
        ax5.set_title('Packet/Flow Statistics', fontweight='bold', fontsize=12)
        ax5.set_xticks(x)
        ax5.set_xticklabels(packet_metrics)
        ax5.legend()
        ax5.grid(True, alpha=0.3, axis='y')
        ax5.set_yscale('log')
        
        save_figure(fig5, f'{base_name}-packet-stats.png', 
                    f'Packet/Flow Statistics\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    
    # 6. Efficiency Metrics Comparison (if packet stats available)
    if baseline_packet_stats or comparison_packet_stats:
        fig6 = plt.figure(figsize=(10, 6))
        ax6 = fig6.add_subplot(1, 1, 1)
        efficiency_metrics = ['Pkts/s per CPU%', 'Flows/s per CPU%', 'MB/s per CPU%']
        baseline_efficiency_values = [
            baseline_cpu_efficiency_packets,
            baseline_cpu_efficiency_flows,
            baseline_cpu_efficiency_bytes / 1e6  # Convert to MB/s per CPU%
        ]
        comparison_efficiency_values = [
            comparison_cpu_efficiency_packets,
            comparison_cpu_efficiency_flows,
            comparison_cpu_efficiency_bytes / 1e6  # Convert to MB/s per CPU%
        ]
        
        x = np.arange(len(efficiency_metrics))
        width = 0.35
        
        bars1 = ax6.bar(x - width/2, baseline_efficiency_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax6.bar(x + width/2, comparison_efficiency_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        # Add percentage change labels
        efficiency_changes = [cpu_efficiency_packets_change, cpu_efficiency_flows_change, cpu_efficiency_bytes_change]
        for i, (base, comp, change) in enumerate(zip(baseline_efficiency_values, comparison_efficiency_values, efficiency_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change > 0 else 'red')
            ax6.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', 
                    fontsize=9, fontweight='bold', color=color)
        
        ax6.set_xlabel('Metric', fontweight='bold')
        ax6.set_ylabel('Efficiency', fontweight='bold')
        ax6.set_title('CPU Efficiency Metrics', fontweight='bold', fontsize=12)
        ax6.set_xticks(x)
        ax6.set_xticklabels(efficiency_metrics, rotation=15, ha='right')
        ax6.legend()
        ax6.grid(True, alpha=0.3, axis='y')
        ax6.set_yscale('log')
        
        save_figure(fig6, f'{base_name}-cpu-efficiency.png', 
                    f'CPU Efficiency Metrics\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    
    # 7. Program Metadata Comparison (Memory, JIT Size, Instructions, Maps)
    fig7 = plt.figure(figsize=(10, 6))
    ax7 = fig7.add_subplot(1, 1, 1)
    metadata_metrics = []
    baseline_metadata_values = []
    comparison_metadata_values = []
    metadata_changes = []
    
    if baseline_total_memlock > 0 or comparison_total_memlock > 0:
        metadata_metrics.append('Memory (MB)')
        baseline_metadata_values.append(baseline_total_memlock / 1e6)
        comparison_metadata_values.append(comparison_total_memlock / 1e6)
        metadata_changes.append(memlock_change)
    
    if baseline_total_jited_size > 0 or comparison_total_jited_size > 0:
        metadata_metrics.append('JIT Size (KB)')
        baseline_metadata_values.append(baseline_total_jited_size / 1e3)
        comparison_metadata_values.append(comparison_total_jited_size / 1e3)
        metadata_changes.append(jited_size_change)
    
    if baseline_total_verified_insns > 0 or comparison_total_verified_insns > 0:
        metadata_metrics.append('Instructions')
        baseline_metadata_values.append(baseline_total_verified_insns)
        comparison_metadata_values.append(comparison_total_verified_insns)
        metadata_changes.append(verified_insns_change)
    
    if baseline_total_maps > 0 or comparison_total_maps > 0:
        metadata_metrics.append('Maps')
        baseline_metadata_values.append(baseline_total_maps)
        comparison_metadata_values.append(comparison_total_maps)
        metadata_changes.append(maps_change)
    
    if metadata_metrics:
        x = np.arange(len(metadata_metrics))
        width = 0.35
        
        bars1 = ax7.bar(x - width/2, baseline_metadata_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax7.bar(x + width/2, comparison_metadata_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        # Add percentage change labels
        for i, (base, comp, change) in enumerate(zip(baseline_metadata_values, comparison_metadata_values, metadata_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change < 0 else 'red')
            ax7.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', 
                    fontsize=9, fontweight='bold', color=color)
        
        ax7.set_xlabel('Metric', fontweight='bold')
        ax7.set_ylabel('Value', fontweight='bold')
        ax7.set_title('Program Metadata Comparison', fontweight='bold', fontsize=12)
        ax7.set_xticks(x)
        ax7.set_xticklabels(metadata_metrics, rotation=15, ha='right')
        ax7.legend()
        ax7.grid(True, alpha=0.3, axis='y')
        ax7.set_yscale('log')
        
        save_figure(fig7, f'{base_name}-program-metadata.png', 
                    f'Program Metadata Comparison\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    else:
        plt.close(fig7)
    
    # 8. Program Metadata by Program (Memory footprint)
    fig8 = plt.figure(figsize=(14, 8))
    ax8 = fig8.add_subplot(1, 1, 1)
    baseline_memlocks = []
    comparison_memlocks = []
    program_labels4 = []
    
    for prog_name in all_programs:
        baseline_prog = baseline_programs.get(prog_name, {})
        comparison_prog = comparison_programs.get(prog_name, {})
        baseline_mem = baseline_prog.get('memlock_bytes', 0) / 1e6  # Convert to MB
        comparison_mem = comparison_prog.get('memlock_bytes', 0) / 1e6
        
        if baseline_mem > 0 or comparison_mem > 0:
            baseline_memlocks.append(baseline_mem)
            comparison_memlocks.append(comparison_mem)
            label = prog_name[:20] + '...' if len(prog_name) > 20 else prog_name
            program_labels4.append(label)
    
    if baseline_memlocks:
        x = np.arange(len(program_labels4))
        width = 0.35
        
        bars1 = ax8.bar(x - width/2, baseline_memlocks, width, label=baseline_label, color='#3498db', alpha=0.8)
        bars2 = ax8.bar(x + width/2, comparison_memlocks, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        
        ax8.set_xlabel('Program', fontweight='bold')
        ax8.set_ylabel('Memory (MB)', fontweight='bold')
        ax8.set_title('Memory Footprint by Program', fontweight='bold', fontsize=12)
        ax8.set_xticks(x)
        ax8.set_xticklabels(program_labels4, rotation=45, ha='right', fontsize=8)
        ax8.legend()
        ax8.grid(True, alpha=0.3, axis='y')
        ax8.set_yscale('log')
        
        save_figure(fig8, f'{base_name}-memory-footprint.png', 
                    f'Memory Footprint by Program\nBaseline: {baseline_label} vs Comparison: {comparison_label}')
    else:
        plt.close(fig8)
    
    # Generate summary text file
    summary_lines = []
    
    # Add cluster information if available
    if cluster_info:
        summary_lines.append("Cluster Information:")
        summary_lines.append(f"  Cluster Name: {cluster_info.get('cluster_name', 'unknown')}")
        summary_lines.append(f"  Cluster Type: {cluster_info.get('cluster_type', 'unknown')}")
        summary_lines.append(f"  Number of Nodes: {cluster_info.get('num_nodes', 'unknown')}")
        
        if 'nodes' in cluster_info and isinstance(cluster_info['nodes'], list):
            # Detailed node information
            instance_types = {}
            for node in cluster_info['nodes']:
                inst_type = node.get('instance_type', 'unknown')
                instance_types[inst_type] = instance_types.get(inst_type, 0) + 1
            
            if instance_types:
                summary_lines.append("  Instance Types:")
                for inst_type, count in sorted(instance_types.items()):
                    summary_lines.append(f"    - {inst_type}: {count} node(s)")
            
            # Show node details if there are few nodes
            if len(cluster_info['nodes']) <= 5:
                summary_lines.append("  Node Details:")
                for node in cluster_info['nodes']:
                    summary_lines.append(f"    - {node.get('name', 'unknown')}: {node.get('instance_type', 'unknown')} "
                                       f"({node.get('cpu', '?')} CPU, {node.get('arch', '?')} arch)")
        elif 'instance_types' in cluster_info:
            # Fallback format
            summary_lines.append(f"  Instance Types: {cluster_info.get('instance_types', 'unknown')}")
        
        summary_lines.append("")  # Empty line separator
    
    summary_lines.extend([
        f"Collection Duration: {duration_sec:.0f}s",
        f"Total CPU: Baseline {baseline_total_cpu:.4f}% | Comparison {comparison_total_cpu:.4f}% | Change: {cpu_change:+.2f}%",
        f"Total Events/sec: Baseline {baseline_total_events:.2f}/s | Comparison {comparison_total_events:.2f}/s | Change: {events_change:+.2f}%",
        f"Avg Runtime/Event: Baseline {baseline_avg_runtime/1e3:.2f}μs | Comparison {comparison_avg_runtime/1e3:.2f}μs | Change: {avg_runtime_change:+.2f}%"
    ])
    
    if baseline_packet_stats or comparison_packet_stats:
        summary_lines.append(f"Packets/sec: Baseline {baseline_packets_per_sec:.2f}/s | Comparison {comparison_packets_per_sec:.2f}/s | Change: {packets_change:+.2f}%")
        summary_lines.append(f"Flows/sec: Baseline {baseline_flows_per_sec:.2f}/s | Comparison {comparison_flows_per_sec:.2f}/s | Change: {flows_change:+.2f}%")
        summary_lines.append(f"Bytes/sec: Baseline {baseline_bytes_per_sec/1e6:.2f}MB/s | Comparison {comparison_bytes_per_sec/1e6:.2f}MB/s | Change: {bytes_change:+.2f}%")
        summary_lines.append(f"CPU Efficiency (pkts/s per %): Baseline {baseline_cpu_efficiency_packets:.2f} | Comparison {comparison_cpu_efficiency_packets:.2f} | Change: {cpu_efficiency_packets_change:+.2f}%")
        summary_lines.append(f"CPU Efficiency (flows/s per %): Baseline {baseline_cpu_efficiency_flows:.2f} | Comparison {comparison_cpu_efficiency_flows:.2f} | Change: {cpu_efficiency_flows_change:+.2f}%")
    
    # Add program metadata to summary
    if baseline_total_memlock > 0 or comparison_total_memlock > 0:
        summary_lines.append(f"Total Memory (MB): Baseline {baseline_total_memlock/1e6:.2f}MB | Comparison {comparison_total_memlock/1e6:.2f}MB | Change: {memlock_change:+.2f}%")
    if baseline_total_jited_size > 0 or comparison_total_jited_size > 0:
        summary_lines.append(f"Total JIT Size (KB): Baseline {baseline_total_jited_size/1e3:.2f}KB | Comparison {comparison_total_jited_size/1e3:.2f}KB | Change: {jited_size_change:+.2f}%")
    if baseline_total_verified_insns > 0 or comparison_total_verified_insns > 0:
        summary_lines.append(f"Total Instructions: Baseline {baseline_total_verified_insns} | Comparison {comparison_total_verified_insns} | Change: {verified_insns_change:+.2f}%")
    if baseline_total_maps > 0 or comparison_total_maps > 0:
        summary_lines.append(f"Total Maps: Baseline {baseline_total_maps} | Comparison {comparison_total_maps} | Change: {maps_change:+.2f}%")
    
    # Create combined figure with all graphs
    # Calculate number of graphs to include
    num_graphs = 5  # cpu-usage, events-per-sec, cpu-total, events-total, avg-runtime-total
    if baseline_runtimes:
        num_graphs += 1  # avg-runtime by program
    if baseline_packet_stats or comparison_packet_stats:
        num_graphs += 2  # packet-stats, cpu-efficiency
    if metadata_metrics:
        num_graphs += 1  # program-metadata
    if baseline_memlocks:
        num_graphs += 1  # memory-footprint
    
    # Create grid layout (3 columns)
    cols = 3
    rows = (num_graphs + cols - 1) // cols
    
    combined_fig = plt.figure(figsize=(20, 6 * rows))
    combined_fig.suptitle(f'eBPF Performance Comparison\nBaseline: {baseline_label} vs Comparison: {comparison_label}', 
                         fontsize=16, fontweight='bold', y=0.995)
    
    subplot_idx = 1
    
    # 1. CPU Usage by Program
    if baseline_cpus:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        x = np.arange(len(program_labels))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_cpus, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_cpus, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        ax_combined.set_xlabel('Program', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('CPU Usage (%)', fontweight='bold', fontsize=9)
        ax_combined.set_title('CPU Usage by Program', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(program_labels, rotation=45, ha='right', fontsize=7)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # 2. Events/sec by Program
    if baseline_events:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        x = np.arange(len(program_labels2))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_events, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_events, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        ax_combined.set_xlabel('Program', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Events/sec', fontweight='bold', fontsize=9)
        ax_combined.set_title('Events/sec by Program', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(program_labels2, rotation=45, ha='right', fontsize=7)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # 3. Total CPU Usage
    ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
    metrics_cpu = ['CPU %']
    baseline_values_cpu = [baseline_total_cpu]
    comparison_values_cpu = [comparison_total_cpu]
    x = np.arange(len(metrics_cpu))
    width = 0.35
    ax_combined.bar(x - width/2, baseline_values_cpu, width, label=baseline_label, color='#3498db', alpha=0.8)
    ax_combined.bar(x + width/2, comparison_values_cpu, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    max_val = max(baseline_total_cpu, comparison_total_cpu) if max(baseline_total_cpu, comparison_total_cpu) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(cpu_change) < 1 else ('green' if cpu_change < 0 else 'red')
    ax_combined.text(0, y_pos, f'{cpu_change:+.2f}%', ha='center', va='bottom', fontsize=9, fontweight='bold', color=color)
    ax_combined.set_ylabel('CPU Usage (%)', fontweight='bold', fontsize=9)
    ax_combined.set_title('Total CPU Usage', fontweight='bold', fontsize=10)
    ax_combined.set_xticks(x)
    ax_combined.set_xticklabels(metrics_cpu, fontsize=9)
    ax_combined.legend(fontsize=8)
    ax_combined.grid(True, alpha=0.3, axis='y')
    subplot_idx += 1
    
    # 4. Total Events/sec
    ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
    metrics_events = ['Events/s']
    baseline_values_events = [baseline_total_events]
    comparison_values_events = [comparison_total_events]
    x = np.arange(len(metrics_events))
    width = 0.35
    ax_combined.bar(x - width/2, baseline_values_events, width, label=baseline_label, color='#3498db', alpha=0.8)
    ax_combined.bar(x + width/2, comparison_values_events, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    max_val = max(baseline_total_events, comparison_total_events) if max(baseline_total_events, comparison_total_events) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(events_change) < 1 else ('green' if events_change > 0 else 'red')
    ax_combined.text(0, y_pos, f'{events_change:+.2f}%', ha='center', va='bottom', fontsize=9, fontweight='bold', color=color)
    ax_combined.set_ylabel('Events/sec', fontweight='bold', fontsize=9)
    ax_combined.set_title('Total Events/sec', fontweight='bold', fontsize=10)
    ax_combined.set_xticks(x)
    ax_combined.set_xticklabels(metrics_events, fontsize=9)
    ax_combined.legend(fontsize=8)
    ax_combined.grid(True, alpha=0.3, axis='y')
    subplot_idx += 1
    
    # 5. Average Runtime per Event
    ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
    metrics_runtime = ['Avg Runtime (μs)']
    baseline_values_runtime = [baseline_avg_runtime / 1e3]
    comparison_values_runtime = [comparison_avg_runtime / 1e3]
    x = np.arange(len(metrics_runtime))
    width = 0.35
    ax_combined.bar(x - width/2, baseline_values_runtime, width, label=baseline_label, color='#3498db', alpha=0.8)
    ax_combined.bar(x + width/2, comparison_values_runtime, width, label=comparison_label, color='#e74c3c', alpha=0.8)
    max_val = max(baseline_values_runtime[0], comparison_values_runtime[0]) if max(baseline_values_runtime[0], comparison_values_runtime[0]) > 0 else 1
    y_pos = max_val * 1.1
    color = 'green' if abs(avg_runtime_change) < 1 else ('green' if avg_runtime_change < 0 else 'red')
    ax_combined.text(0, y_pos, f'{avg_runtime_change:+.2f}%', ha='center', va='bottom', fontsize=9, fontweight='bold', color=color)
    ax_combined.set_ylabel('Average Runtime (μs)', fontweight='bold', fontsize=9)
    ax_combined.set_title('Avg Runtime per Event', fontweight='bold', fontsize=10)
    ax_combined.set_xticks(x)
    ax_combined.set_xticklabels(metrics_runtime, fontsize=9)
    ax_combined.legend(fontsize=8)
    ax_combined.grid(True, alpha=0.3, axis='y')
    subplot_idx += 1
    
    # 6. Average Runtime by Program (if available)
    if baseline_runtimes:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        x = np.arange(len(program_labels3))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_runtimes, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_runtimes, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        ax_combined.set_xlabel('Program', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Avg Runtime (μs)', fontweight='bold', fontsize=9)
        ax_combined.set_title('Avg Runtime by Program', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(program_labels3, rotation=45, ha='right', fontsize=7)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # 7. Packet Stats (if available)
    if baseline_packet_stats or comparison_packet_stats:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        packet_metrics = ['Packets/s', 'Flows/s', 'Bytes/s (MB)']
        baseline_packet_values = [
            baseline_packets_per_sec,
            baseline_flows_per_sec,
            baseline_bytes_per_sec / 1e6
        ]
        comparison_packet_values = [
            comparison_packets_per_sec,
            comparison_flows_per_sec,
            comparison_bytes_per_sec / 1e6
        ]
        x = np.arange(len(packet_metrics))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_packet_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_packet_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        packet_changes = [packets_change, flows_change, bytes_change]
        for i, (base, comp, change) in enumerate(zip(baseline_packet_values, comparison_packet_values, packet_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change > 0 else 'red')
            ax_combined.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', fontsize=8, fontweight='bold', color=color)
        ax_combined.set_xlabel('Metric', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Rate', fontweight='bold', fontsize=9)
        ax_combined.set_title('Packet/Flow Statistics', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(packet_metrics, fontsize=8)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
        
        # 8. CPU Efficiency (if available)
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        efficiency_metrics = ['Pkts/s per CPU%', 'Flows/s per CPU%', 'MB/s per CPU%']
        baseline_efficiency_values = [
            baseline_cpu_efficiency_packets,
            baseline_cpu_efficiency_flows,
            baseline_cpu_efficiency_bytes / 1e6
        ]
        comparison_efficiency_values = [
            comparison_cpu_efficiency_packets,
            comparison_cpu_efficiency_flows,
            comparison_cpu_efficiency_bytes / 1e6
        ]
        x = np.arange(len(efficiency_metrics))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_efficiency_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_efficiency_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        efficiency_changes = [cpu_efficiency_packets_change, cpu_efficiency_flows_change, cpu_efficiency_bytes_change]
        for i, (base, comp, change) in enumerate(zip(baseline_efficiency_values, comparison_efficiency_values, efficiency_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change > 0 else 'red')
            ax_combined.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', fontsize=8, fontweight='bold', color=color)
        ax_combined.set_xlabel('Metric', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Efficiency', fontweight='bold', fontsize=9)
        ax_combined.set_title('CPU Efficiency Metrics', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(efficiency_metrics, rotation=15, ha='right', fontsize=8)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # 9. Program Metadata (if available)
    if metadata_metrics:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        x = np.arange(len(metadata_metrics))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_metadata_values, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_metadata_values, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        for i, (base, comp, change) in enumerate(zip(baseline_metadata_values, comparison_metadata_values, metadata_changes)):
            max_val = max(base, comp) if max(base, comp) > 0 else 1
            y_pos = max_val * 1.1
            color = 'green' if abs(change) < 1 else ('green' if change < 0 else 'red')
            ax_combined.text(i, y_pos, f'{change:+.1f}%', ha='center', va='bottom', fontsize=8, fontweight='bold', color=color)
        ax_combined.set_xlabel('Metric', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Value', fontweight='bold', fontsize=9)
        ax_combined.set_title('Program Metadata', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(metadata_metrics, rotation=15, ha='right', fontsize=8)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # 10. Memory Footprint by Program (if available)
    if baseline_memlocks:
        ax_combined = combined_fig.add_subplot(rows, cols, subplot_idx)
        x = np.arange(len(program_labels4))
        width = 0.35
        ax_combined.bar(x - width/2, baseline_memlocks, width, label=baseline_label, color='#3498db', alpha=0.8)
        ax_combined.bar(x + width/2, comparison_memlocks, width, label=comparison_label, color='#e74c3c', alpha=0.8)
        ax_combined.set_xlabel('Program', fontweight='bold', fontsize=9)
        ax_combined.set_ylabel('Memory (MB)', fontweight='bold', fontsize=9)
        ax_combined.set_title('Memory Footprint by Program', fontweight='bold', fontsize=10)
        ax_combined.set_xticks(x)
        ax_combined.set_xticklabels(program_labels4, rotation=45, ha='right', fontsize=7)
        ax_combined.legend(fontsize=8)
        ax_combined.grid(True, alpha=0.3, axis='y')
        ax_combined.set_yscale('log')
        subplot_idx += 1
    
    # Add timestamp to combined figure
    combined_fig.text(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 
                     ha='right', va='bottom', fontsize=8, style='italic')
    
    # Adjust layout and save combined figure
    plt.tight_layout(rect=[0, 0.03, 1, 0.97])
    combined_fig.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close(combined_fig)
    print(f"Combined comparison report generated: {output_file}")
    generated_files.append(Path(output_file))
    
    summary_text = "\n".join(summary_lines)
    summary_file = base_dir / f'{base_name}-summary.txt'
    with open(summary_file, 'w') as f:
        f.write(f"eBPF Performance Comparison Summary\n")
        f.write(f"Baseline: {baseline_label} vs Comparison: {comparison_label}\n")
        f.write(f"{'='*60}\n\n")
        f.write(summary_text)
        f.write(f"\n\n{'='*60}\n")
        f.write(f"Generated Graphs:\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"Combined Report:\n")
        f.write(f"  - {output_path.name}\n\n")
        f.write(f"Individual Graphs:\n")
        
        # List all generated graph files
        graph_files = [
            (f'{base_name}-cpu-usage.png', 'CPU Usage by Program'),
            (f'{base_name}-events-per-sec.png', 'Events/sec by Program'),
            (f'{base_name}-cpu-total.png', 'Total CPU Usage Comparison'),
            (f'{base_name}-events-total.png', 'Total Events/sec Comparison'),
            (f'{base_name}-avg-runtime-total.png', 'Average Runtime per Event Comparison'),
            (f'{base_name}-avg-runtime.png', 'Average Runtime by Program'),
        ]
        
        if baseline_packet_stats or comparison_packet_stats:
            graph_files.extend([
                (f'{base_name}-packet-stats.png', 'Packet/Flow Statistics'),
                (f'{base_name}-cpu-efficiency.png', 'CPU Efficiency Metrics'),
            ])
        
        if metadata_metrics:
            graph_files.append((f'{base_name}-program-metadata.png', 'Program Metadata Comparison'))
        
        if baseline_memlocks:
            graph_files.append((f'{base_name}-memory-footprint.png', 'Memory Footprint by Program'))
        
        for filename, description in graph_files:
            filepath = base_dir / filename
            if filepath.exists():
                f.write(f"  - {filename} ({description})\n")
        
        f.write(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"Summary generated: {summary_file}")
    generated_files.append(summary_file)
    
    print(f"\nAll comparison graphs generated ({len(generated_files)} files)")
    print(f"Base output directory: {base_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='Compare kernel stats from two benchmark runs and generate matplotlib visualizations',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--baseline', required=True, help='Baseline kernel stats JSON file')
    parser.add_argument('--comparison', required=True, help='Comparison kernel stats JSON file')
    parser.add_argument('--output', required=True, help='Output PNG image file')
    parser.add_argument('--baseline-label', default='Baseline', help='Label for baseline image')
    parser.add_argument('--comparison-label', default='Comparison', help='Label for comparison image')
    parser.add_argument('--baseline-packet-stats', help='Baseline packet stats JSON file (optional)')
    parser.add_argument('--comparison-packet-stats', help='Comparison packet stats JSON file (optional)')
    parser.add_argument('--cluster-info', help='Cluster information JSON file (optional, auto-detected if in same directory as baseline)')
    
    args = parser.parse_args()
    
    # Auto-detect cluster-info.json in the same directory as baseline file if not provided
    cluster_info = None
    if args.cluster_info:
        cluster_info_path = Path(args.cluster_info)
    else:
        # Try to find cluster-info.json in the same directory as baseline file
        baseline_path = Path(args.baseline)
        cluster_info_path = baseline_path.parent / 'cluster-info.json'
    
    if cluster_info_path.exists():
        try:
            cluster_info = load_stats(str(cluster_info_path))
            print(f"Loaded cluster information from: {cluster_info_path}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load cluster info from {cluster_info_path}: {e}", file=sys.stderr)
            cluster_info = None
    
    baseline_stats = load_stats(args.baseline)
    comparison_stats = load_stats(args.comparison)
    
    baseline_packet_stats = None
    comparison_packet_stats = None
    
    if args.baseline_packet_stats:
        if Path(args.baseline_packet_stats).exists():
            try:
                baseline_packet_stats = load_stats(args.baseline_packet_stats)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"Warning: Could not load baseline packet stats from {args.baseline_packet_stats}: {e}", file=sys.stderr)
                baseline_packet_stats = None
        else:
            print(f"Warning: Baseline packet stats file not found: {args.baseline_packet_stats}", file=sys.stderr)
    
    if args.comparison_packet_stats:
        if Path(args.comparison_packet_stats).exists():
            try:
                comparison_packet_stats = load_stats(args.comparison_packet_stats)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"Warning: Could not load comparison packet stats from {args.comparison_packet_stats}: {e}", file=sys.stderr)
                comparison_packet_stats = None
        else:
            print(f"Warning: Comparison packet stats file not found: {args.comparison_packet_stats}", file=sys.stderr)
    
    generate_matplotlib_report(
        baseline_stats,
        comparison_stats,
        args.baseline_label,
        args.comparison_label,
        args.output,
        baseline_packet_stats,
        comparison_packet_stats,
        cluster_info
    )


if __name__ == '__main__':
    main()

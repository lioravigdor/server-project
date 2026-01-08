#!/usr/bin/env python3
"""
Authentication Log Analyzer - Formal Report Generator

Analyzes authentication attempt logs and produces citation-ready statistics
for security reports. Supports both attack-side and server-side log formats.

Usage:
    python log_analyzer.py <logfile> [--csv output.csv]
"""

import json
import csv
import argparse
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# =============================================================================
# LOG PARSING
# =============================================================================

def parse_log_file(filepath: str) -> list[dict]:
    """
    Parse a JSON-lines log file. Supports both attack-side and server-side formats.
    
    Attack-side format: timestamp, username, password_tried, result, latency_ms, attack_type
    Server-side format: timestamp, username, hash_mode, protection_flags, result, latency_ms, group_seed
    """
    entries = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping malformed JSON at line {line_num}: {e}")
    return entries


def detect_log_type(entries: list[dict]) -> str:
    """Detect whether this is an attack-side or server-side log."""
    if not entries:
        return "unknown"
    
    sample = entries[0]
    if "password_tried" in sample or "attack_type" in sample:
        return "attack"
    elif "hash_mode" in sample or "protection_flags" in sample:
        return "server"
    else:
        return "unknown"


# =============================================================================
# STATISTICS COMPUTATION
# =============================================================================

def compute_executive_summary(entries: list[dict]) -> dict:
    """Compute executive summary statistics."""
    if not entries:
        return {}
    
    timestamps = [e["timestamp"] for e in entries]
    start_time = min(timestamps)
    end_time = max(timestamps)
    duration = end_time - start_time
    
    total_attempts = len(entries)
    successes = sum(1 for e in entries if e.get("result") == "Success")
    failures = total_attempts - successes
    success_rate = (successes / total_attempts * 100) if total_attempts > 0 else 0
    
    unique_users = len(set(e.get("username", "") for e in entries))
    
    return {
        "total_attempts": total_attempts,
        "successes": successes,
        "failures": failures,
        "success_rate": success_rate,
        "unique_users": unique_users,
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": duration,
    }


def compute_attack_type_stats(entries: list[dict]) -> dict:
    """Compute statistics by attack type (for attack-side logs)."""
    attack_stats = defaultdict(lambda: {"attempts": 0, "successes": 0, "failures": 0})
    
    for entry in entries:
        attack_type = entry.get("attack_type", "unknown")
        attack_stats[attack_type]["attempts"] += 1
        if entry.get("result") == "Success":
            attack_stats[attack_type]["successes"] += 1
        else:
            attack_stats[attack_type]["failures"] += 1
    
    # Calculate success rates
    for attack_type in attack_stats:
        stats = attack_stats[attack_type]
        attempts = stats["attempts"]
        stats["success_rate"] = (stats["successes"] / attempts * 100) if attempts > 0 else 0
    
    return dict(attack_stats)


def compute_hash_mode_latency(entries: list[dict]) -> dict:
    """Compute latency statistics by hash mode (for server-side logs)."""
    latencies_by_mode = defaultdict(list)
    
    for entry in entries:
        hash_mode = entry.get("hash_mode")
        latency = entry.get("latency_ms")
        if hash_mode and latency is not None:
            # Handle enum-style hash_mode values like "HashMode.SHA256"
            if "." in str(hash_mode):
                hash_mode = str(hash_mode).split(".")[-1].lower()
            latencies_by_mode[hash_mode].append(latency)
    
    stats = {}
    for mode, latencies in latencies_by_mode.items():
        if latencies:
            stats[mode] = {
                "mean": statistics.mean(latencies),
                "median": statistics.median(latencies),
                "stdev": statistics.stdev(latencies) if len(latencies) > 1 else 0,
                "min": min(latencies),
                "max": max(latencies),
                "count": len(latencies),
            }
    
    return stats


def compute_response_patterns(entries: list[dict]) -> dict:
    """Compute server response pattern statistics."""
    if not entries:
        return {}
    
    timestamps = sorted(e["timestamp"] for e in entries)
    latencies = [e.get("latency_ms", 0) for e in entries]
    
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
    
    # Requests per second
    if duration > 0:
        mean_rps = len(entries) / duration
        # Calculate peak RPS using 1-second windows
        window_counts = Counter(int(ts) for ts in timestamps)
        peak_rps = max(window_counts.values()) if window_counts else 0
    else:
        mean_rps = len(entries)
        peak_rps = len(entries)
    
    # Latency percentiles
    sorted_latencies = sorted(latencies)
    n = len(sorted_latencies)
    
    def percentile(p):
        if n == 0:
            return 0
        idx = int(p / 100 * n)
        return sorted_latencies[min(idx, n - 1)]
    
    return {
        "mean_rps": mean_rps,
        "peak_rps": peak_rps,
        "duration_seconds": duration,
        "latency_p50": percentile(50),
        "latency_p90": percentile(90),
        "latency_p99": percentile(99),
        "latency_mean": statistics.mean(latencies) if latencies else 0,
    }


def compute_password_analysis(entries: list[dict]) -> dict:
    """Compute password analysis (for attack-side logs)."""
    passwords = [e.get("password_tried") for e in entries if e.get("password_tried")]
    
    if not passwords:
        return {}
    
    password_counts = Counter(passwords)
    successful_passwords = [
        e.get("password_tried") 
        for e in entries 
        if e.get("result") == "Success" and e.get("password_tried")
    ]
    
    return {
        "unique_passwords": len(set(passwords)),
        "total_password_attempts": len(passwords),
        "top_10_passwords": password_counts.most_common(10),
        "successful_passwords": list(set(successful_passwords)),
    }


def compute_user_statistics(entries: list[dict]) -> dict:
    """Compute overall user statistics."""
    user_attempts = Counter(e.get("username") for e in entries)
    user_successes = Counter(
        e.get("username") for e in entries if e.get("result") == "Success"
    )
    
    attempt_counts = list(user_attempts.values())
    
    if not attempt_counts:
        return {}
    
    users_with_success = sum(1 for u in user_successes if user_successes[u] > 0)
    
    return {
        "unique_users": len(user_attempts),
        "attempts_mean": statistics.mean(attempt_counts),
        "attempts_median": statistics.median(attempt_counts),
        "attempts_max": max(attempt_counts),
        "attempts_min": min(attempt_counts),
        "users_compromised": users_with_success,
        "compromise_rate": (users_with_success / len(user_attempts) * 100) if user_attempts else 0,
    }


def compute_all_statistics(entries: list[dict], log_type: str) -> dict:
    """Compute all statistics for the log file."""
    return {
        "log_type": log_type,
        "executive_summary": compute_executive_summary(entries),
        "attack_types": compute_attack_type_stats(entries),
        "hash_mode_latency": compute_hash_mode_latency(entries),
        "response_patterns": compute_response_patterns(entries),
        "password_analysis": compute_password_analysis(entries),
        "user_statistics": compute_user_statistics(entries),
    }


# =============================================================================
# PRETTY STDOUT FORMATTER
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def format_timestamp(ts: float) -> str:
    """Format Unix timestamp to readable string."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"


def print_box(title: str, width: int = 70):
    """Print a boxed section header."""
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * width}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {title.upper()}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * width}{Colors.END}")


def print_table(headers: list[str], rows: list[list], col_widths: list[int] = None):
    """Print a formatted table."""
    if not col_widths:
        col_widths = [max(len(str(headers[i])), max(len(str(row[i])) for row in rows) if rows else 0) + 2 
                      for i in range(len(headers))]
    
    # Header
    header_line = "│".join(f" {h:<{col_widths[i]-1}}" for i, h in enumerate(headers))
    print(f"  {Colors.BOLD}{header_line}{Colors.END}")
    
    # Separator
    sep_line = "┼".join("─" * w for w in col_widths)
    print(f"  {sep_line}")
    
    # Rows
    for row in rows:
        row_line = "│".join(f" {str(v):<{col_widths[i]-1}}" for i, v in enumerate(row))
        print(f"  {row_line}")


def print_metric(label: str, value, unit: str = "", highlight: bool = False):
    """Print a single metric line."""
    color = Colors.GREEN if highlight else ""
    end = Colors.END if highlight else ""
    if unit:
        print(f"  • {label}: {color}{value}{end} {unit}")
    else:
        print(f"  • {label}: {color}{value}{end}")


def print_report(stats: dict):
    """Print the formatted report to stdout."""
    log_type = stats.get("log_type", "unknown")
    exec_summary = stats.get("executive_summary", {})
    attack_types = stats.get("attack_types", {})
    hash_latency = stats.get("hash_mode_latency", {})
    response = stats.get("response_patterns", {})
    passwords = stats.get("password_analysis", {})
    users = stats.get("user_statistics", {})
    
    # Title
    print()
    print(f"{Colors.BOLD}{Colors.HEADER}╔══════════════════════════════════════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}║          AUTHENTICATION LOG ANALYSIS REPORT                          ║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}╚══════════════════════════════════════════════════════════════════════╝{Colors.END}")
    print(f"  Log Type: {log_type.upper()}")
    
    # Section 1: Executive Summary
    print_box("Section 1: Executive Summary")
    if exec_summary:
        print_metric("Total Attempts", f"{exec_summary.get('total_attempts', 0):,}")
        print_metric("Successful", f"{exec_summary.get('successes', 0):,}", highlight=exec_summary.get('successes', 0) > 0)
        print_metric("Failed", f"{exec_summary.get('failures', 0):,}")
        print_metric("Success Rate", f"{exec_summary.get('success_rate', 0):.2f}", "%", highlight=True)
        print_metric("Unique Users Targeted", exec_summary.get('unique_users', 0))
        print()
        print_metric("Time Range Start", format_timestamp(exec_summary.get('start_time', 0)))
        print_metric("Time Range End", format_timestamp(exec_summary.get('end_time', 0)))
        print_metric("Total Duration", format_duration(exec_summary.get('duration_seconds', 0)))
    
    # Section 2: Attack Type Comparison
    print_box("Section 2: Attack Type Comparison")
    if attack_types:
        headers = ["Attack Type", "Attempts", "Successes", "Failures", "Success Rate (%)"]
        rows = []
        for attack_type, data in sorted(attack_types.items()):
            rows.append([
                attack_type,
                f"{data['attempts']:,}",
                f"{data['successes']:,}",
                f"{data['failures']:,}",
                f"{data['success_rate']:.2f}"
            ])
        print_table(headers, rows, [18, 12, 12, 12, 18])
    else:
        print("  No attack type data available (server-side log)")
    
    # Section 3: Hash Algorithm Latency Impact
    print_box("Section 3: Hash Algorithm Latency Impact")
    if hash_latency:
        headers = ["Hash Mode", "Mean (ms)", "Median (ms)", "Std Dev", "Min (ms)", "Max (ms)"]
        rows = []
        for mode, data in sorted(hash_latency.items()):
            rows.append([
                mode,
                f"{data['mean']:.3f}",
                f"{data['median']:.3f}",
                f"{data['stdev']:.3f}",
                f"{data['min']:.3f}",
                f"{data['max']:.3f}"
            ])
        print_table(headers, rows, [12, 12, 12, 12, 12, 12])
    else:
        print("  No hash mode data available (attack-side log)")
    
    # Section 4: Server Response Patterns
    print_box("Section 4: Server Response Patterns")
    if response:
        print_metric("Mean Requests/Second", f"{response.get('mean_rps', 0):.2f}")
        print_metric("Peak Requests/Second", f"{response.get('peak_rps', 0):,}")
        print_metric("Total Duration", format_duration(response.get('duration_seconds', 0)))
        print()
        print(f"  {Colors.BOLD}Latency Percentiles:{Colors.END}")
        print_metric("  P50 (Median)", f"{response.get('latency_p50', 0):.3f}", "ms")
        print_metric("  P90", f"{response.get('latency_p90', 0):.3f}", "ms")
        print_metric("  P99", f"{response.get('latency_p99', 0):.3f}", "ms")
        print_metric("  Mean", f"{response.get('latency_mean', 0):.3f}", "ms")
    
    # Section 5: Password Analysis
    print_box("Section 5: Password Analysis")
    if passwords and passwords.get("unique_passwords"):
        print_metric("Unique Passwords Attempted", f"{passwords.get('unique_passwords', 0):,}")
        print_metric("Total Password Attempts", f"{passwords.get('total_password_attempts', 0):,}")
        print()
        
        top_passwords = passwords.get("top_10_passwords", [])
        if top_passwords:
            print(f"  {Colors.BOLD}Top 10 Most Tried Passwords:{Colors.END}")
            headers = ["Rank", "Password", "Attempts"]
            rows = [[i+1, pwd, f"{count:,}"] for i, (pwd, count) in enumerate(top_passwords)]
            print_table(headers, rows, [8, 25, 12])
        
        successful = passwords.get("successful_passwords", [])
        if successful:
            print()
            print(f"  {Colors.BOLD}{Colors.RED}Passwords That Led to Successful Auth:{Colors.END}")
            for pwd in successful:
                print(f"    → {Colors.RED}{pwd}{Colors.END}")
    else:
        print("  No password data available (server-side log)")
    
    # Section 6: Overall Statistics
    print_box("Section 6: Overall Statistics")
    if users:
        print_metric("Unique Users Targeted", f"{users.get('unique_users', 0):,}")
        print_metric("Users Compromised", f"{users.get('users_compromised', 0):,}", highlight=users.get('users_compromised', 0) > 0)
        print_metric("Compromise Rate", f"{users.get('compromise_rate', 0):.2f}", "%", highlight=True)
        print()
        print(f"  {Colors.BOLD}Attempts Per User:{Colors.END}")
        print_metric("  Mean", f"{users.get('attempts_mean', 0):.2f}")
        print_metric("  Median", f"{users.get('attempts_median', 0):.1f}")
        print_metric("  Min", f"{users.get('attempts_min', 0):,}")
        print_metric("  Max", f"{users.get('attempts_max', 0):,}")
    
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}")
    print(f"{Colors.BOLD}  END OF REPORT{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}")
    print()


# =============================================================================
# CSV EXPORT
# =============================================================================

def export_csv(stats: dict, output_path: str):
    """Export statistics to CSV file with category/metric/value/unit format."""
    rows = []
    
    # Executive Summary
    exec_summary = stats.get("executive_summary", {})
    rows.append(["executive_summary", "total_attempts", exec_summary.get("total_attempts", 0), "count"])
    rows.append(["executive_summary", "successes", exec_summary.get("successes", 0), "count"])
    rows.append(["executive_summary", "failures", exec_summary.get("failures", 0), "count"])
    rows.append(["executive_summary", "success_rate", f"{exec_summary.get('success_rate', 0):.4f}", "percent"])
    rows.append(["executive_summary", "unique_users", exec_summary.get("unique_users", 0), "count"])
    rows.append(["executive_summary", "duration", f"{exec_summary.get('duration_seconds', 0):.2f}", "seconds"])
    rows.append(["executive_summary", "start_time", exec_summary.get("start_time", 0), "unix_timestamp"])
    rows.append(["executive_summary", "end_time", exec_summary.get("end_time", 0), "unix_timestamp"])
    
    # Attack Types
    for attack_type, data in stats.get("attack_types", {}).items():
        rows.append(["attack_type", f"{attack_type}_attempts", data.get("attempts", 0), "count"])
        rows.append(["attack_type", f"{attack_type}_successes", data.get("successes", 0), "count"])
        rows.append(["attack_type", f"{attack_type}_failures", data.get("failures", 0), "count"])
        rows.append(["attack_type", f"{attack_type}_success_rate", f"{data.get('success_rate', 0):.4f}", "percent"])
    
    # Hash Mode Latency
    for mode, data in stats.get("hash_mode_latency", {}).items():
        rows.append(["hash_latency", f"{mode}_mean", f"{data.get('mean', 0):.6f}", "ms"])
        rows.append(["hash_latency", f"{mode}_median", f"{data.get('median', 0):.6f}", "ms"])
        rows.append(["hash_latency", f"{mode}_stdev", f"{data.get('stdev', 0):.6f}", "ms"])
        rows.append(["hash_latency", f"{mode}_min", f"{data.get('min', 0):.6f}", "ms"])
        rows.append(["hash_latency", f"{mode}_max", f"{data.get('max', 0):.6f}", "ms"])
        rows.append(["hash_latency", f"{mode}_count", data.get("count", 0), "count"])
    
    # Response Patterns
    response = stats.get("response_patterns", {})
    rows.append(["response_patterns", "mean_rps", f"{response.get('mean_rps', 0):.4f}", "requests/second"])
    rows.append(["response_patterns", "peak_rps", response.get("peak_rps", 0), "requests/second"])
    rows.append(["response_patterns", "latency_p50", f"{response.get('latency_p50', 0):.6f}", "ms"])
    rows.append(["response_patterns", "latency_p90", f"{response.get('latency_p90', 0):.6f}", "ms"])
    rows.append(["response_patterns", "latency_p99", f"{response.get('latency_p99', 0):.6f}", "ms"])
    rows.append(["response_patterns", "latency_mean", f"{response.get('latency_mean', 0):.6f}", "ms"])
    
    # Password Analysis
    passwords = stats.get("password_analysis", {})
    rows.append(["password_analysis", "unique_passwords", passwords.get("unique_passwords", 0), "count"])
    rows.append(["password_analysis", "total_attempts", passwords.get("total_password_attempts", 0), "count"])
    
    top_passwords = passwords.get("top_10_passwords", [])
    for i, (pwd, count) in enumerate(top_passwords, 1):
        rows.append(["password_analysis", f"top_{i}_password", pwd, "password"])
        rows.append(["password_analysis", f"top_{i}_count", count, "count"])
    
    successful = passwords.get("successful_passwords", [])
    for i, pwd in enumerate(successful, 1):
        rows.append(["password_analysis", f"successful_password_{i}", pwd, "password"])
    
    # User Statistics
    users = stats.get("user_statistics", {})
    rows.append(["user_statistics", "unique_users", users.get("unique_users", 0), "count"])
    rows.append(["user_statistics", "users_compromised", users.get("users_compromised", 0), "count"])
    rows.append(["user_statistics", "compromise_rate", f"{users.get('compromise_rate', 0):.4f}", "percent"])
    rows.append(["user_statistics", "attempts_mean", f"{users.get('attempts_mean', 0):.4f}", "count"])
    rows.append(["user_statistics", "attempts_median", f"{users.get('attempts_median', 0):.4f}", "count"])
    rows.append(["user_statistics", "attempts_min", users.get("attempts_min", 0), "count"])
    rows.append(["user_statistics", "attempts_max", users.get("attempts_max", 0), "count"])
    
    # Write CSV
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["category", "metric_name", "value", "unit"])
        writer.writerows(rows)
    
    print(f"{Colors.GREEN}✓ CSV exported to: {output_path}{Colors.END}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Authentication Log Analyzer - Formal Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py spray_attack.log
  python log_analyzer.py ../server/attempts.log --csv results.csv
        """
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--csv", metavar="OUTPUT", help="Export results to CSV file")
    
    args = parser.parse_args()
    
    # Validate input file
    logfile = Path(args.logfile)
    if not logfile.exists():
        print(f"{Colors.RED}Error: Log file not found: {logfile}{Colors.END}")
        return 1
    
    # Parse log file
    print(f"Loading log file: {logfile}")
    entries = parse_log_file(str(logfile))
    
    if not entries:
        print(f"{Colors.RED}Error: No valid log entries found{Colors.END}")
        return 1
    
    print(f"Parsed {len(entries):,} log entries")
    
    # Detect log type
    log_type = detect_log_type(entries)
    print(f"Detected log type: {log_type}")
    
    # Compute statistics
    stats = compute_all_statistics(entries, log_type)
    
    # Print report
    print_report(stats)
    
    # Export CSV if requested
    if args.csv:
        export_csv(stats, args.csv)
    
    return 0


if __name__ == "__main__":
    exit(main())

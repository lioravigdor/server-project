#!/usr/bin/env python3
"""
Experiment Runner - Automated Protection Comparison Tester

Orchestrates end-to-end testing by starting servers with different protection
configurations, running attacks against each, and generating comparative analysis.

Usage:
    python experiment_runner.py                              # Run all configs
    python experiment_runner.py --configs baseline rate_limit # Run specific configs
    python experiment_runner.py --max-attempts 500 --time-limit 60
"""

import sys
import json
import time
import shutil
import argparse
import subprocess
import csv
from pathlib import Path
from datetime import datetime
from typing import Optional

import requests


# =============================================================================
# PREDEFINED CONFIGURATIONS
# =============================================================================

PREDEFINED_CONFIGS = {
    # Baseline tests (no protections, different hashes)
    "baseline": {
        "protections": [],
        "hash": "sha256",
        "description": "No protections, SHA256 hashing (control group)"
    },
    "bcrypt_only": {
        "protections": [],
        "hash": "bcrypt",
        "description": "No protections, bcrypt hashing (slow hash)"
    },
    "argon2_only": {
        "protections": [],
        "hash": "argon2",
        "description": "No protections, Argon2 hashing (memory-hard)"
    },
    
    # Single protection tests
    "rate_limit": {
        "protections": ["rate_limiting"],
        "hash": "sha256",
        "description": "Rate limiting only"
    },
    "lockout": {
        "protections": ["account_lockout"],
        "hash": "sha256",
        "description": "Account lockout only"
    },
    "captcha": {
        "protections": ["captcha"],
        "hash": "sha256",
        "description": "CAPTCHA only"
    },
    
    # Combined protections
    "rate_lockout": {
        "protections": ["rate_limiting", "account_lockout"],
        "hash": "sha256",
        "description": "Rate limiting + account lockout"
    },
    "lockout_captcha": {
        "protections": ["account_lockout", "captcha"],
        "hash": "sha256",
        "description": "Account lockout + CAPTCHA"
    },
    
    # Hash + protection combos
    "bcrypt_lockout": {
        "protections": ["account_lockout"],
        "hash": "bcrypt",
        "description": "Bcrypt + account lockout"
    },
    "argon2_lockout": {
        "protections": ["account_lockout"],
        "hash": "argon2",
        "description": "Argon2 + account lockout"
    },
    
    # Full protection
    "full_protection": {
        "protections": ["all"],
        "hash": "bcrypt",
        "description": "All protections with bcrypt"
    },
    "full_argon2": {
        "protections": ["all"],
        "hash": "argon2",
        "description": "All protections with Argon2"
    },
}

# Paths
PROJECT_ROOT = Path(__file__).parent
SERVER_DIR = PROJECT_ROOT / "server"
ATTACKS_DIR = PROJECT_ROOT / "attacks"
BRUTE_FORCER = ATTACKS_DIR / "brute_forcer" / "brute_forcer.py"
PASSWORD_SPRAYER = ATTACKS_DIR / "password_sprayer" / "password_sprayer.py"
RESULTS_DIR = PROJECT_ROOT / "experiment_results"

# Defaults
DEFAULT_MAX_ATTEMPTS = 200
DEFAULT_TIME_LIMIT = 60
SERVER_PORT = 8000
SERVER_HOST = "127.0.0.1"
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

# Brute force targets - three from each password strength level
DEFAULT_BRUTE_TARGETS = [
    # Weak passwords (easy to crack)
    "weak_user_01",    # 123456
    "weak_user_02",    # password
    "weak_user_03",    # qwerty
    # Medium passwords (harder)
    "medium_user_01",  # Summer2024!
    "medium_user_02",  # Password123
    "medium_user_03",  # Football99
    # Strong passwords (very hard)
    "strong_user_01",  # kX9#mP2$vL7@nQ4
    "strong_user_02",  # 7Fj!qR3&wZ8*pK5
    "strong_user_03",  # Bx4$nT9#hL2@yM6
]


# =============================================================================
# SERVER MANAGEMENT
# =============================================================================

class ServerManager:
    """Manages server lifecycle for experiments."""
    
    def __init__(self, config_id: str, config: dict, output_dir: Path):
        self.config_id = config_id
        self.config = config
        self.output_dir = output_dir
        self.process: Optional[subprocess.Popen] = None
        self.log_file: Optional[Path] = None
    
    def _build_server_command(self) -> list[str]:
        """Build the server command with appropriate flags."""
        cmd = [sys.executable, "main.py", "--host", SERVER_HOST, "--port", str(SERVER_PORT)]
        
        # Add hash mode
        cmd.extend(["--hash", self.config["hash"]])
        
        # Add protections
        protections = self.config.get("protections", [])
        if protections:
            cmd.append("--protect")
            cmd.extend(protections)
        else:
            cmd.extend(["--protect", "none"])
        
        return cmd
    
    def reset_database(self):
        """Delete users.db to ensure clean state."""
        db_path = SERVER_DIR / "users.db"
        if db_path.exists():
            db_path.unlink()
            print(f"  [*] Deleted existing users.db")
        
        # Also clear attempts.log
        log_path = SERVER_DIR / "attempts.log"
        if log_path.exists():
            log_path.unlink()
            print(f"  [*] Cleared attempts.log")
    
    def start(self) -> bool:
        """Start the server and wait for it to be ready."""
        # Kill any existing server on the port first
        self._kill_port_processes()
        time.sleep(1)  # Give OS time to release the port
        
        self.reset_database()
        
        cmd = self._build_server_command()
        print(f"  [*] Starting server: {' '.join(cmd)}")
        
        # Create log file for server output
        self.log_file = self.output_dir / "server.log"
        self.log_handle = open(self.log_file, 'w')
        
        # Start server process
        self.process = subprocess.Popen(
            cmd,
            cwd=SERVER_DIR,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
        )
        
        # Wait for server to be ready
        return self._wait_for_ready()
    
    def _wait_for_ready(self, timeout: int = 30) -> bool:
        """Wait for server to respond to health check."""
        print(f"  [*] Waiting for server to be ready...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Try a simple request to check if server is up
                response = requests.get(f"{SERVER_URL}/docs", timeout=2)
                if response.status_code == 200:
                    print(f"  [+] Server ready after {time.time() - start_time:.1f}s")
                    return True
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.Timeout:
                pass
            
            # Check if process died
            if self.process.poll() is not None:
                print(f"  [!] Server process died with code {self.process.returncode}")
                return False
            
            time.sleep(0.5)
        
        print(f"  [!] Server failed to start within {timeout}s")
        return False
    
    def stop(self):
        """Stop the server gracefully."""
        if self.process is None:
            return
        
        print(f"  [*] Stopping server...")
        
        try:
            # Terminate the process
            self.process.terminate()
            
            # Wait for graceful shutdown
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f"  [!] Force killing server...")
            self.process.kill()
            self.process.wait()
        except Exception as e:
            print(f"  [!] Error stopping server: {e}")
        
        # Close log file handle
        if hasattr(self, 'log_handle') and self.log_handle:
            self.log_handle.close()
        
        self.process = None
        
        # Kill any remaining processes on the port
        self._kill_port_processes()
        
        print(f"  [+] Server stopped")
    
    def _kill_port_processes(self):
        """Kill any processes still bound to the server port (excluding self)."""
        import os
        my_pid = os.getpid()
        
        try:
            # Find processes using the port
            result = subprocess.run(
                ["lsof", "-ti", f":{SERVER_PORT}"],
                capture_output=True,
                text=True
            )
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid and pid.isdigit() and int(pid) != my_pid:
                    subprocess.run(["kill", "-9", pid], capture_output=True)
                    print(f"  [*] Killed orphan process {pid}")
        except Exception:
            pass  # lsof might not be available on all systems
    
    def collect_logs(self, phase: str = ""):
        """Copy server logs to output directory."""
        attempts_log = SERVER_DIR / "attempts.log"
        if attempts_log.exists():
            suffix = f"_{phase}" if phase else ""
            shutil.copy(attempts_log, self.output_dir / f"server_attempts{suffix}.log")
            print(f"  [*] Collected server attempts log ({phase or 'all'})")


# =============================================================================
# ATTACK EXECUTION
# =============================================================================

class AttackRunner:
    """Runs attacks against the server."""
    
    def __init__(self, output_dir: Path, max_attempts: int, time_limit: int, brute_targets: list[str]):
        self.output_dir = output_dir
        self.max_attempts = max_attempts
        self.time_limit = time_limit
        self.brute_targets = brute_targets
    
    def run_brute_force(self) -> dict:
        """Run brute force attacks on multiple targets and return combined results."""
        print(f"  [*] Running brute force attacks on {len(self.brute_targets)} targets...")
        
        all_results = {
            "targets": {},
            "summary": {
                "total_attempts": 0,
                "total_successes": 0,
                "targets_cracked": 0,
                "total_time_s": 0,
                "avg_attempts_per_second": 0,
            }
        }
        
        total_aps = 0
        
        for target in self.brute_targets:
            print(f"    [*] Target: {target}")
            
            log_file = self.output_dir / f"brute_{target}.log"
            output_file = self.output_dir / f"brute_{target}_results.json"
            
            cmd = [
                sys.executable, str(BRUTE_FORCER),
                "--username", target,
                "--base-url", SERVER_URL,
                "--max-attempts", str(self.max_attempts),
                "--time-limit", str(self.time_limit),
                "--log", str(log_file),
                "--output", str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=ATTACKS_DIR / "brute_forcer"
            )
            
            # Save stdout
            with open(self.output_dir / f"brute_{target}_stdout.txt", 'w') as f:
                f.write(result.stdout)
            
            # Load and aggregate results
            target_result = {"exit_code": result.returncode}
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                    target_result["data"] = data
                    
                    # Aggregate stats
                    all_results["summary"]["total_attempts"] += data.get("total_attempts", 0)
                    all_results["summary"]["total_successes"] += data.get("successes", 0)
                    all_results["summary"]["total_time_s"] += data.get("time_elapsed_s", 0)
                    all_results["summary"]["rate_limited"] = all_results["summary"].get("rate_limited", 0) + data.get("rate_limited", 0)
                    all_results["summary"]["locked_out"] = all_results["summary"].get("locked_out", 0) + data.get("locked_out", 0)
                    # Use effective APS (excludes blocked attempts)
                    total_aps += data.get("effective_aps", data.get("attempts_per_second", 0))
                    
                    if data.get("successes", 0) > 0:
                        all_results["summary"]["targets_cracked"] += 1
            
            all_results["targets"][target] = target_result
            
            status = "CRACKED" if target_result.get("data", {}).get("successes", 0) > 0 else "secure"
            print(f"    [+] {target}: {status}")
        
        # Calculate average APS
        if len(self.brute_targets) > 0:
            all_results["summary"]["avg_attempts_per_second"] = total_aps / len(self.brute_targets)
        
        # Save combined results
        with open(self.output_dir / "brute_results.json", 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"  [+] Brute force complete: {all_results['summary']['targets_cracked']}/{len(self.brute_targets)} cracked")
        return all_results
    
    def run_password_spray(self) -> dict:
        """Run password spray attack and return results."""
        print(f"  [*] Running password spray attack...")
        
        log_file = self.output_dir / "spray_attack.log"
        output_file = self.output_dir / "spray_results.json"
        
        cmd = [
            sys.executable, str(PASSWORD_SPRAYER),
            "--base-url", SERVER_URL,
            "--max-attempts", str(self.max_attempts),
            "--time-limit", str(self.time_limit),
            "--log", str(log_file),
            "--output", str(output_file)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=ATTACKS_DIR / "password_sprayer"
        )
        
        # Save stdout/stderr
        with open(self.output_dir / "spray_stdout.txt", 'w') as f:
            f.write(result.stdout)
        if result.stderr:
            with open(self.output_dir / "spray_stderr.txt", 'w') as f:
                f.write(result.stderr)
        
        # Load results if available
        results = {"exit_code": result.returncode, "stdout": result.stdout}
        if output_file.exists():
            with open(output_file) as f:
                results["data"] = json.load(f)
        
        print(f"  [+] Password spray complete (exit code: {result.returncode})")
        return results


# =============================================================================
# ANALYSIS
# =============================================================================

def analyze_config(config_dir: Path) -> dict:
    """Analyze results for a single configuration."""
    analysis = {
        "brute_force": {},
        "password_spray": {},
        "server_brute": {},
        "server_spray": {}
    }
    
    # Load brute force results
    brute_results = config_dir / "brute_results.json"
    if brute_results.exists():
        with open(brute_results) as f:
            data = json.load(f)
            # Handle new multi-target format
            if "summary" in data:
                analysis["brute_force"] = data["summary"]
                analysis["brute_force"]["targets"] = data.get("targets", {})
            else:
                analysis["brute_force"] = data
    
    # Load spray results
    spray_results = config_dir / "spray_results.json"
    if spray_results.exists():
        with open(spray_results) as f:
            analysis["password_spray"] = json.load(f)
    
    # Analyze server attempts logs (separate for brute and spray)
    for phase in ["brute", "spray"]:
        attempts_log = config_dir / f"server_attempts_{phase}.log"
        if attempts_log.exists():
            with open(attempts_log) as f:
                attempts = [json.loads(line) for line in f if line.strip()]
            
            if attempts:
                successes = sum(1 for a in attempts if a.get("result") == "Success")
                analysis[f"server_{phase}"] = {
                    "total_attempts": len(attempts),
                    "successes": successes,
                    "failures": len(attempts) - successes,
                    "success_rate": (successes / len(attempts) * 100) if attempts else 0
                }
    
    return analysis


def generate_comparative_report(experiment_dir: Path, configs: list[str]) -> dict:
    """Generate comparative report across all configurations."""
    print("\n[*] Generating comparative report...")
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "experiment_dir": str(experiment_dir),
        "configurations": {},
        "summary": {
            "by_success_rate": [],
            "by_attempts_per_second": [],
            "by_users_cracked": []
        }
    }
    
    for config_id in configs:
        config_dir = experiment_dir / f"config_{config_id}"
        if not config_dir.exists():
            continue
        
        config_data = PREDEFINED_CONFIGS.get(config_id, {})
        analysis = analyze_config(config_dir)
        
        report["configurations"][config_id] = {
            "description": config_data.get("description", ""),
            "protections": config_data.get("protections", []),
            "hash_mode": config_data.get("hash", ""),
            "analysis": analysis
        }
        
        # Extract summary metrics
        brute = analysis.get("brute_force", {})
        spray = analysis.get("password_spray", {})
        
        report["summary"]["by_success_rate"].append({
            "config": config_id,
            "brute_cracked": brute.get("targets_cracked", brute.get("successes", 0)),
            "spray_users_cracked": spray.get("users_cracked", 0)
        })
        
        report["summary"]["by_attempts_per_second"].append({
            "config": config_id,
            "brute_aps": brute.get("avg_attempts_per_second", brute.get("attempts_per_second", 0)),
            "spray_aps": spray.get("attempts_per_second", 0)
        })
        
        report["summary"]["by_users_cracked"].append({
            "config": config_id,
            "spray_cracked": spray.get("users_cracked", 0),
            "spray_total": spray.get("total_users", 0),
            "brute_cracked": brute.get("targets_cracked", brute.get("successes", 0)),
            "brute_total": len(brute.get("targets", {})) or 1
        })
    
    # Sort summaries (lower cracked = better, then lower APS = better)
    report["summary"]["by_success_rate"].sort(key=lambda x: x["spray_users_cracked"] + x["brute_cracked"])
    report["summary"]["by_users_cracked"].sort(key=lambda x: x["spray_cracked"] + x["brute_cracked"])
    
    # Determine best/worst protection
    # Best = fewest cracked, then lowest APS (attacker slowed down most)
    # Worst = most cracked, then highest APS (attacker fastest)
    if report["summary"]["by_users_cracked"]:
        # Use brute APS for ranking (effective APS excludes blocked attempts)
        aps_by_config = {item["config"]: item["brute_aps"] for item in report["summary"]["by_attempts_per_second"]}
        
        sorted_configs = sorted(
            report["summary"]["by_users_cracked"],
            key=lambda x: (x["spray_cracked"] + x["brute_cracked"], aps_by_config.get(x["config"], 0))
        )
        report["best_protection"] = sorted_configs[0]["config"]
        
        sorted_worst = sorted(
            report["summary"]["by_users_cracked"],
            key=lambda x: (-(x["spray_cracked"] + x["brute_cracked"]), -aps_by_config.get(x["config"], 0))
        )
        report["most_vulnerable"] = sorted_worst[0]["config"]
    
    return report


def export_comparative_csv(report: dict, output_path: Path):
    """Export comparative report as CSV."""
    rows = []
    
    for config_id, config_data in report.get("configurations", {}).items():
        analysis = config_data.get("analysis", {})
        brute = analysis.get("brute_force", {})
        spray = analysis.get("password_spray", {})
        server_brute = analysis.get("server_brute", {})
        server_spray = analysis.get("server_spray", {})
        
        rows.append({
            "config_id": config_id,
            "description": config_data.get("description", ""),
            "protections": ",".join(config_data.get("protections", [])) or "none",
            "hash_mode": config_data.get("hash_mode", ""),
            # Brute force stats
            "brute_attempts": brute.get("total_attempts", 0),
            "brute_targets_cracked": brute.get("targets_cracked", brute.get("successes", 0)),
            "brute_total_targets": len(brute.get("targets", {})) or 1,
            "brute_aps": f"{brute.get('avg_attempts_per_second', brute.get('attempts_per_second', 0)):.2f}",
            "brute_time_s": f"{brute.get('total_time_s', brute.get('time_elapsed_s', 0)):.2f}",
            # Spray stats
            "spray_attempts": spray.get("total_attempts", 0),
            "spray_users_cracked": spray.get("users_cracked", 0),
            "spray_total_users": spray.get("total_users", 0),
            "spray_aps": f"{spray.get('attempts_per_second', 0):.2f}",
            "spray_avg_latency_ms": f"{spray.get('avg_latency_ms', 0):.2f}",
            # Server stats
            "server_brute_attempts": server_brute.get("total_attempts", 0),
            "server_brute_successes": server_brute.get("successes", 0),
            "server_spray_attempts": server_spray.get("total_attempts", 0),
            "server_spray_successes": server_spray.get("successes", 0),
        })
    
    if rows:
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"  [+] CSV exported to: {output_path}")


def print_summary(report: dict):
    """Print a nice summary to stdout."""
    print("\n" + "=" * 120)
    print("EXPERIMENT SUMMARY")
    print("=" * 120)
    
    configs = report.get("configurations", {})
    
    # Header
    print(f"\n{'Config':<16} {'Protection':<12} {'Hash':<6} {'Spray':<7} {'Brute':<7} {'EffAPS':<7} {'Blocked':<8} {'Time(s)':<8}")
    print("-" * 120)
    
    for config_id, data in configs.items():
        protections = ",".join(data.get("protections", [])) or "none"
        if len(protections) > 10:
            protections = protections[:8] + ".."
        hash_mode = data.get("hash_mode", "")[:5]
        
        spray = data.get("analysis", {}).get("password_spray", {})
        brute = data.get("analysis", {}).get("brute_force", {})
        
        spray_cracked = f"{spray.get('users_cracked', 0)}/{spray.get('total_users', 0)}"
        brute_targets = len(brute.get('targets', {}))
        brute_successes = brute.get('targets_cracked', brute.get('successes', 0))
        brute_cracked = f"{brute_successes}/{brute_targets}" if brute_targets > 0 else "-"
        
        # Effective APS (actual auth attempts only)
        eff_aps = f"{brute.get('avg_attempts_per_second', brute.get('attempts_per_second', 0)):.1f}"
        
        # Blocked attempts (rate limited + locked out)
        blocked = brute.get('rate_limited', 0) + brute.get('locked_out', 0)
        blocked_str = str(blocked) if blocked > 0 else "-"
        
        # Total time for brute force
        brute_time = f"{brute.get('total_time_s', 0):.1f}"
        
        print(f"{config_id:<16} {protections:<12} {hash_mode:<6} {spray_cracked:<7} {brute_cracked:<7} {eff_aps:<7} {blocked_str:<8} {brute_time:<8}")
    
    print("-" * 120)
    
    print("\nEffAPS = Effective Attempts/Second (excludes blocked requests)")
    print("Blocked = Rate-limited (429) + Locked-out (403) attempts")
    
    if report.get("best_protection"):
        print(f"\n[+] BEST PROTECTION: {report['best_protection']}")
    if report.get("most_vulnerable"):
        print(f"[!] MOST VULNERABLE: {report['most_vulnerable']}")
    
    print("=" * 120)


# =============================================================================
# MAIN ORCHESTRATION
# =============================================================================

def run_experiment(
    configs: list[str],
    max_attempts: int,
    time_limit: int,
    brute_targets: list[str]
) -> Path:
    """Run the full experiment."""
    
    # Create experiment directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = RESULTS_DIR / f"experiment_{timestamp}"
    experiment_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'=' * 70}")
    print(f"PROTECTION COMPARISON EXPERIMENT")
    print(f"{'=' * 70}")
    print(f"Experiment ID: {timestamp}")
    print(f"Output directory: {experiment_dir}")
    print(f"Configurations: {', '.join(configs)}")
    print(f"Max attempts per attack: {max_attempts}")
    print(f"Time limit per attack: {time_limit}s")
    print(f"Brute force targets: {', '.join(brute_targets)}")
    print(f"{'=' * 70}\n")
    
    # Save experiment settings
    settings = {
        "timestamp": timestamp,
        "configs": configs,
        "max_attempts": max_attempts,
        "time_limit": time_limit,
        "brute_targets": brute_targets
    }
    with open(experiment_dir / "settings.json", 'w') as f:
        json.dump(settings, f, indent=2)
    
    # Run each configuration
    for i, config_id in enumerate(configs, 1):
        print(f"\n[{i}/{len(configs)}] Running configuration: {config_id}")
        print("-" * 50)
        
        config = PREDEFINED_CONFIGS.get(config_id)
        if not config:
            print(f"  [!] Unknown configuration: {config_id}, skipping")
            continue
        
        print(f"  Description: {config['description']}")
        print(f"  Protections: {config['protections'] or 'none'}")
        print(f"  Hash: {config['hash']}")
        
        # Create config output directory
        config_dir = experiment_dir / f"config_{config_id}"
        config_dir.mkdir(exist_ok=True)
        
        # Save config metadata
        with open(config_dir / "config.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        # Start server
        server = ServerManager(config_id, config, config_dir)
        if not server.start():
            print(f"  [!] Failed to start server for {config_id}")
            server.stop()
            continue
        
        try:
            # Run attacks
            attacker = AttackRunner(config_dir, max_attempts, time_limit, brute_targets)
            
            # Run brute force attacks
            print(f"\n  --- BRUTE FORCE PHASE ---")
            brute_results = attacker.run_brute_force()
            
            # Collect brute force logs before reset
            server.collect_logs("brute")
            
            # Restart server for spray attack (clean slate with fresh users)
            print(f"\n  --- RESTARTING SERVER FOR SPRAY PHASE ---")
            server.stop()
            time.sleep(1)
            if not server.start():
                print(f"  [!] Failed to restart server for spray phase")
                continue
            
            # Run password spray attack
            print(f"\n  --- PASSWORD SPRAY PHASE ---")
            spray_results = attacker.run_password_spray()
            
            # Collect spray logs
            server.collect_logs("spray")
            
        finally:
            # Always stop server
            server.stop()
        
        # Pause between configs to ensure port is released
        time.sleep(2)
    
    # Generate comparative report
    report = generate_comparative_report(experiment_dir, configs)
    
    # Save report
    report_json = experiment_dir / "comparative_report.json"
    with open(report_json, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"  [+] Report saved to: {report_json}")
    
    # Export CSV
    report_csv = experiment_dir / "comparative_report.csv"
    export_comparative_csv(report, report_csv)
    
    # Print summary
    print_summary(report)
    
    print(f"\n[+] Experiment complete! Results in: {experiment_dir}\n")
    
    return experiment_dir


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Automated Protection Comparison Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Available configurations:
  {', '.join(PREDEFINED_CONFIGS.keys())}

Examples:
  python experiment_runner.py                                    # Run all configs
  python experiment_runner.py --configs baseline rate_limit      # Run specific configs
  python experiment_runner.py --max-attempts 500 --time-limit 120
        """
    )
    
    parser.add_argument(
        "--configs", "-c",
        nargs="*",
        default=list(PREDEFINED_CONFIGS.keys()),
        choices=list(PREDEFINED_CONFIGS.keys()),
        metavar="CONFIG",
        help=f"Configurations to test (default: all)"
    )
    
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=f"Max attempts per attack (default: {DEFAULT_MAX_ATTEMPTS})"
    )
    
    parser.add_argument(
        "--time-limit",
        type=int,
        default=DEFAULT_TIME_LIMIT,
        help=f"Time limit per attack in seconds (default: {DEFAULT_TIME_LIMIT})"
    )
    
    parser.add_argument(
        "--brute-targets",
        nargs="*",
        default=DEFAULT_BRUTE_TARGETS,
        metavar="USER",
        help=f"Target users for brute force attack (default: {', '.join(DEFAULT_BRUTE_TARGETS)})"
    )
    
    parser.add_argument(
        "--list-configs",
        action="store_true",
        help="List available configurations and exit"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # List configs if requested
    if args.list_configs:
        print("\nAvailable configurations:\n")
        for config_id, config in PREDEFINED_CONFIGS.items():
            protections = ", ".join(config["protections"]) or "none"
            print(f"  {config_id:<20} - {config['description']}")
            print(f"  {'':<20}   Protections: {protections}, Hash: {config['hash']}\n")
        return 0
    
    # Run experiment
    try:
        run_experiment(
            configs=args.configs,
            max_attempts=args.max_attempts,
            time_limit=args.time_limit,
            brute_targets=args.brute_targets
        )
        return 0
    except KeyboardInterrupt:
        print("\n[!] Experiment interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Experiment failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
smallbank_benchmark.py - SmallBank Benchmark Implementation for PBFT

SmallBank simulates a banking application with:
- 3 tables: customers, savings, checking
- 6 transaction types: Balance, DepositChecking, TransactSavings, 
  Amalgamate, WriteCheck, SendPayment
- Skewed access pattern (Zipf distribution)

This integrates with existing PBFT system without modifying core logic.
"""

import random
import time
import json
import socket
import threading
import statistics
from collections import defaultdict
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt

# Configuration
HOST = "127.0.0.1"
PROTO_PORTS = [7000 + i for i in range(7)]
TIMEOUT = 5.0

# SmallBank Configuration
NUM_ACCOUNTS = 100  # Configurable: 100, 1000, 10000
INITIAL_BALANCE = 10000
ZIPF_ALPHA = 0.9  # Skewness parameter (higher = more skewed)

# Transaction Types (as per SmallBank spec)
TXN_TYPES = {
    'BALANCE': 0.15,           # 15% - Read checking + savings balance
    'DEPOSIT_CHECKING': 0.15,  # 15% - Deposit to checking
    'TRANSACT_SAVINGS': 0.15,  # 15% - Add/subtract from savings
    'AMALGAMATE': 0.15,        # 15% - Transfer savings -> checking
    'WRITE_CHECK': 0.25,       # 25% - Write check (deduct from checking)
    'SEND_PAYMENT': 0.15       # 15% - Transfer between accounts
}

class SmallBankBenchmark:
    """SmallBank benchmark implementation"""
    
    def __init__(self, num_accounts=NUM_ACCOUNTS, num_clients=10):
        self.num_accounts = num_accounts
        self.num_clients = num_clients
        
        # Three tables (as per SmallBank spec)
        self.customers = {}    # customer_id -> name
        self.savings = {}      # customer_id -> balance
        self.checking = {}     # customer_id -> balance
        
        # Performance metrics
        self.latencies = []
        self.throughput_data = []
        self.txn_type_counts = defaultdict(int)
        self.successful_txns = 0
        self.failed_txns = 0
        self.start_time = None
        self.end_time = None
        
        # Zipf distribution for skewed access
        self.zipf_distribution = self._generate_zipf_distribution()
        
        print(f"[SmallBank] Initialized with {num_accounts} accounts, {num_clients} clients")
    
    def _generate_zipf_distribution(self) -> List[int]:
        """Generate Zipf distribution for skewed account access"""
        # Create weights following Zipf distribution
        weights = [1.0 / (i ** ZIPF_ALPHA) for i in range(1, self.num_accounts + 1)]
        total = sum(weights)
        probabilities = [w / total for w in weights]
        
        # Pre-compute distribution (for efficiency)
        distribution = []
        for i, prob in enumerate(probabilities):
            count = int(prob * 10000)  # Scale for granularity
            distribution.extend([i] * count)
        
        return distribution
    
    def initialize_database(self) -> Dict[str, Any]:
        """Initialize SmallBank database state"""
        for i in range(self.num_accounts):
            customer_id = f"C{i:06d}"
            self.customers[customer_id] = f"Customer_{i}"
            self.savings[customer_id] = INITIAL_BALANCE
            self.checking[customer_id] = INITIAL_BALANCE
        
        print(f"[SmallBank] Database initialized: {self.num_accounts} accounts")
        print(f"[SmallBank] Initial balances: Savings={INITIAL_BALANCE}, Checking={INITIAL_BALANCE}")
        
        return {
            'customers': self.customers,
            'savings': dict(self.savings),
            'checking': dict(self.checking)
        }
    
    def get_random_account(self) -> str:
        """Get random account using Zipf distribution (skewed access)"""
        if self.zipf_distribution:
            idx = random.choice(self.zipf_distribution)
            return f"C{idx:06d}"
        else:
            idx = random.randint(0, self.num_accounts - 1)
            return f"C{idx:06d}"
    
    def get_random_accounts(self, n: int) -> List[str]:
        """Get n different random accounts"""
        accounts = set()
        while len(accounts) < n:
            accounts.add(self.get_random_account())
        return list(accounts)
    
    def generate_transaction(self) -> Tuple[str, Dict[str, Any]]:
        """Generate a random SmallBank transaction"""
        # Select transaction type based on distribution
        rand = random.random()
        cumulative = 0.0
        txn_type = None
        
        for ttype, prob in TXN_TYPES.items():
            cumulative += prob
            if rand <= cumulative:
                txn_type = ttype
                break
        
        if txn_type is None:
            txn_type = 'BALANCE'
        
        self.txn_type_counts[txn_type] += 1
        
        # Generate transaction based on type
        if txn_type == 'BALANCE':
            # Read balance of checking + savings
            account = self.get_random_account()
            return txn_type, {
                'type': 'BALANCE',
                'account': account
            }
        
        elif txn_type == 'DEPOSIT_CHECKING':
            # Deposit amount into checking
            account = self.get_random_account()
            amount = random.randint(100, 1000)
            return txn_type, {
                'type': 'DEPOSIT_CHECKING',
                'account': account,
                'amount': amount
            }
        
        elif txn_type == 'TRANSACT_SAVINGS':
            # Add or subtract from savings
            account = self.get_random_account()
            amount = random.randint(-500, 500)
            return txn_type, {
                'type': 'TRANSACT_SAVINGS',
                'account': account,
                'amount': amount
            }
        
        elif txn_type == 'AMALGAMATE':
            # Transfer all savings to checking (single account)
            account = self.get_random_account()
            return txn_type, {
                'type': 'AMALGAMATE',
                'account': account
            }
        
        elif txn_type == 'WRITE_CHECK':
            # Write check (deduct from checking)
            account = self.get_random_account()
            amount = random.randint(100, 500)
            return txn_type, {
                'type': 'WRITE_CHECK',
                'account': account,
                'amount': amount
            }
        
        elif txn_type == 'SEND_PAYMENT':
            # Transfer between two accounts
            accounts = self.get_random_accounts(2)
            amount = random.randint(100, 1000)
            return txn_type, {
                'type': 'SEND_PAYMENT',
                'from_account': accounts[0],
                'to_account': accounts[1],
                'amount': amount
            }
        
        return txn_type, {'type': 'BALANCE', 'account': self.get_random_account()}
    
    def encode_transaction_for_pbft(self, txn_data: Dict[str, Any]) -> tuple:
        """
        Encode SmallBank transaction into PBFT-compatible format
        
        PBFT expects: (sender, receiver, amount) or ("READ", account)
        We extend to: ("SMALLBANK", json_string, txn_type)
        """
        txn_json = json.dumps(txn_data, sort_keys=True)
        return ("SMALLBANK", txn_json, txn_data['type'])
    
    def send_transaction_to_pbft(self, txn: tuple, primary_port: int) -> Dict[str, Any]:
        """Send transaction to PBFT primary and wait for response - FIXED"""
        request = {
            "type": "REQUEST",
            "client_id": random.randint(0, self.num_clients - 1),
            "request": txn,
            "timestamp": int(time.time() * 1000)
        }
        
        sock = None
        try:
            # Create connection but DON'T use 'with' - manage lifetime manually
            sock = socket.create_connection((HOST, primary_port), timeout=TIMEOUT)
            sock.settimeout(20.0)  # Long timeout for execution
            sock.sendall((json.dumps(request) + "\n").encode())
            
            buf = b""
            got_queued = False
            start_time = time.time()
            
            while time.time() - start_time < 20.0:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        # Connection closed
                        if got_queued:
                            return {"error": "connection-closed-after-queued"}
                        return {"error": "connection-closed"}
                    
                    buf += chunk
                    
                    # Process all complete messages in buffer
                    while b"\n" in buf:
                        line, _, buf = buf.partition(b"\n")
                        try:
                            response = json.loads(line.decode())
                            
                            # If we get "queued", keep waiting for REPLY
                            if response.get("result") == "queued":
                                got_queued = True
                                continue  # Keep connection open, wait for REPLY
                            
                            # If we get REPLY, we're done
                            if response.get("type") == "REPLY":
                                return response
                            
                            # If we get redirect, return it
                            if response.get("result") == "redirect":
                                return response
                            
                            # Any other response, return it
                            return response
                            
                        except json.JSONDecodeError:
                            continue
                
                except socket.timeout:
                    if got_queued:
                        # Still waiting for execution
                        continue
                    return {"error": "timeout"}
            
            return {"error": "timeout-waiting-for-reply"}
            
        except socket.timeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
        finally:
            # Always close socket when done
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def run_benchmark(self, duration_seconds: int = 60, warmup_seconds: int = 10):
        """
        Run SmallBank benchmark for specified duration
        
        Args:
            duration_seconds: Benchmark duration (excluding warmup)
            warmup_seconds: Warmup period before measurement
        """
        print(f"\n{'='*70}")
        print(f"SmallBank Benchmark Starting")
        print(f"{'='*70}")
        print(f"Configuration:")
        print(f"  Accounts: {self.num_accounts}")
        print(f"  Clients: {self.num_clients}")
        print(f"  Duration: {duration_seconds}s (+ {warmup_seconds}s warmup)")
        print(f"  Zipf alpha: {ZIPF_ALPHA}")
        print(f"{'='*70}\n")
        
        # Find primary
        primary_port = PROTO_PORTS[0]  # Assume node 0 is primary
        
        # Warmup phase
        print(f"[SmallBank] Warmup phase ({warmup_seconds}s)...")
        warmup_end = time.time() + warmup_seconds
        warmup_count = 0
        while time.time() < warmup_end:
            _, txn_data = self.generate_transaction()
            txn = self.encode_transaction_for_pbft(txn_data)
            response = self.send_transaction_to_pbft(txn, primary_port)
            warmup_count += 1
            time.sleep(0.1)
        
        print(f"[SmallBank] Warmup complete ({warmup_count} transactions)")
        
        # Reset counters for measurement phase
        self.latencies = []
        self.successful_txns = 0
        self.failed_txns = 0
        self.txn_type_counts.clear()
        
        print(f"[SmallBank] Starting measurement phase ({duration_seconds}s)...")
        self.start_time = time.time()
        end_time = self.start_time + duration_seconds
        
        txn_count = 0
        last_report_time = self.start_time
        
        while time.time() < end_time:
            # Generate and send transaction
            txn_type, txn_data = self.generate_transaction()
            txn = self.encode_transaction_for_pbft(txn_data)
            
            start = time.time()
            response = self.send_transaction_to_pbft(txn, primary_port)
            latency = (time.time() - start) * 1000  # milliseconds
            
            self.latencies.append(latency)
            
            # Check for success - REPLY with result field
            if response.get("type") == "REPLY":
                result = response.get("result", "")
                if result == "success":
                    self.successful_txns += 1
                else:
                    self.failed_txns += 1
            elif response.get("error"):
                self.failed_txns += 1
                # On connection error, brief pause before continuing
                if "connection" in response.get("error", ""):
                    time.sleep(0.2)
            else:
                self.failed_txns += 1
            
            txn_count += 1
            
            # Progress report every 10 seconds
            if time.time() - last_report_time >= 10.0:
                elapsed = time.time() - self.start_time
                throughput = txn_count / elapsed
                avg_latency = statistics.mean(self.latencies[-100:]) if len(self.latencies) >= 100 else statistics.mean(self.latencies)
                success_rate = (self.successful_txns / txn_count * 100) if txn_count > 0 else 0
                print(f"[SmallBank] Progress: {int(elapsed)}s, {txn_count} txns, "
                      f"{throughput:.2f} txn/s, {avg_latency:.2f}ms avg latency ")
                last_report_time = time.time()
            
            # Small delay to avoid overwhelming system
            time.sleep(0.05)
        
        self.end_time = time.time()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive benchmark report"""
        duration = self.end_time - self.start_time
        total_txns = self.successful_txns + self.failed_txns
        throughput = total_txns / duration
        
        print(f"\n{'='*70}")
        print(f"SmallBank Benchmark Results")
        print(f"{'='*70}")
        print(f"Duration: {duration:.2f}s")
        print(f"Total Transactions: {total_txns}")
        print(f"  Successful: {self.successful_txns} ({100*self.successful_txns/total_txns:.1f}%)")
        print(f"  Failed: {self.failed_txns} ({100*self.failed_txns/total_txns:.1f}%)")
        print(f"\nThroughput: {throughput:.2f} txn/s")
        
        if self.latencies:
            print(f"\nLatency Statistics (ms):")
            print(f"  Mean: {statistics.mean(self.latencies):.2f}")
            print(f"  Median: {statistics.median(self.latencies):.2f}")
            print(f"  P50: {self._percentile(self.latencies, 50):.2f}")
            print(f"  P95: {self._percentile(self.latencies, 95):.2f}")
            print(f"  P99: {self._percentile(self.latencies, 99):.2f}")
            print(f"  Min: {min(self.latencies):.2f}")
            print(f"  Max: {max(self.latencies):.2f}")
        
        print(f"\nTransaction Type Distribution:")
        for txn_type, count in sorted(self.txn_type_counts.items()):
            percentage = 100 * count / total_txns
            print(f"  {txn_type:20s}: {count:6d} ({percentage:5.1f}%)")
        
        print(f"{'='*70}\n")
        
        # Save results to file
        self.save_results()
        
        # Generate plots
        self.plot_results()
    
    def _percentile(self, data: List[float], p: float) -> float:
        """Calculate percentile"""
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[-1]
        d0 = sorted_data[f] * (c - k)
        d1 = sorted_data[c] * (k - f)
        return d0 + d1
    
    def save_results(self):
        """Save benchmark results to JSON file"""
        results = {
            'config': {
                'num_accounts': self.num_accounts,
                'num_clients': self.num_clients,
                'duration': self.end_time - self.start_time,
                'zipf_alpha': ZIPF_ALPHA
            },
            'summary': {
                'total_txns': self.successful_txns + self.failed_txns,
                'successful_txns': self.successful_txns + self.failed_txns,
                'throughput': (self.successful_txns + self.failed_txns) / (self.end_time - self.start_time)
            },
            'latency': {
                'mean': statistics.mean(self.latencies),
                'median': statistics.median(self.latencies),
                'p50': self._percentile(self.latencies, 50),
                'p95': self._percentile(self.latencies, 95),
                'p99': self._percentile(self.latencies, 99),
                'min': min(self.latencies),
                'max': max(self.latencies)
            },
            'transaction_types': dict(self.txn_type_counts)
        }
        
        filename = f"smallbank_results_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[SmallBank] Results saved to {filename}")
    
    def plot_results(self):
        """Generate performance visualization plots"""
        try:
            # Create figure with subplots
            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle('SmallBank Benchmark Results', fontsize=16)
            
            # Plot 1: Latency distribution
            axes[0, 0].hist(self.latencies, bins=50, color='skyblue', edgecolor='black')
            axes[0, 0].set_xlabel('Latency (ms)')
            axes[0, 0].set_ylabel('Frequency')
            axes[0, 0].set_title('Latency Distribution')
            axes[0, 0].axvline(statistics.mean(self.latencies), color='red', linestyle='--', label='Mean')
            axes[0, 0].axvline(statistics.median(self.latencies), color='green', linestyle='--', label='Median')
            axes[0, 0].legend()
            
            # Plot 2: Latency over time
            time_points = [(i / len(self.latencies)) * (self.end_time - self.start_time) 
                          for i in range(len(self.latencies))]
            axes[0, 1].plot(time_points, self.latencies, alpha=0.5, linewidth=0.5)
            axes[0, 1].set_xlabel('Time (s)')
            axes[0, 1].set_ylabel('Latency (ms)')
            axes[0, 1].set_title('Latency Over Time')
            
            # Plot 3: Transaction type distribution
            txn_types = list(self.txn_type_counts.keys())
            txn_counts = list(self.txn_type_counts.values())
            axes[1, 0].bar(txn_types, txn_counts, color='lightcoral')
            axes[1, 0].set_xlabel('Transaction Type')
            axes[1, 0].set_ylabel('Count')
            axes[1, 0].set_title('Transaction Type Distribution')
            axes[1, 0].tick_params(axis='x', rotation=45)
            
            # Plot 4: Cumulative latency percentiles
            sorted_latencies = sorted(self.latencies)
            percentiles = [(i / len(sorted_latencies)) * 100 for i in range(len(sorted_latencies))]
            axes[1, 1].plot(percentiles, sorted_latencies, color='purple')
            axes[1, 1].set_xlabel('Percentile')
            axes[1, 1].set_ylabel('Latency (ms)')
            axes[1, 1].set_title('Cumulative Latency Distribution')
            axes[1, 1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            filename = f"smallbank_plots_{int(time.time())}.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"[SmallBank] Plots saved to {filename}")
            
            # Try to show plot (if in interactive environment)
            try:
                plt.show()
            except:
                pass
        
        except Exception as e:
            print(f"[SmallBank] Warning: Could not generate plots: {e}")


def main():
    """Main benchmark execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SmallBank Benchmark for PBFT')
    parser.add_argument('--accounts', type=int, default=100,
                       help='Number of accounts (default: 100)')
    parser.add_argument('--clients', type=int, default=10,
                       help='Number of concurrent clients (default: 10)')
    parser.add_argument('--duration', type=int, default=60,
                       help='Benchmark duration in seconds (default: 60)')
    parser.add_argument('--warmup', type=int, default=10,
                       help='Warmup duration in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Create benchmark instance
    benchmark = SmallBankBenchmark(
        num_accounts=args.accounts,
        num_clients=args.clients
    )
    
    # Initialize database state
    initial_state = benchmark.initialize_database()
    print(f"[SmallBank] Database ready with {len(initial_state['customers'])} customers")
    
    # Run benchmark
    benchmark.run_benchmark(
        duration_seconds=args.duration,
        warmup_seconds=args.warmup
    )


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
pbft_server.py - WITH EQUIVOCATION ATTACK IMPLEMENTATION
Critical features:
1. Primary sends PRE-PREPARE to all backups properly
2. Backups receive PRE-PREPARE and send PREPARE to primary
3. Primary collects PREPAREs and broadcasts COLLECT_PREPARES
4. Proper signature validation rejects invalid signatures
5. Byzantine nodes with invalid signatures excluded from quorums
6. CRASH ATTACK: Byzantine node refuses to participate in protocol
7. CRASH DETECTION: Backups detect crashed primary and initiate view change
8. TIMING ATTACK: Byzantine primary deliberately delays messages
9. DARK ATTACK: Byzantine primary excludes specific nodes from communication
10. EQUIVOCATION ATTACK: Byzantine primary sends different sequence numbers to different nodes
11. SET_VIEW command: Properly set view and role across all nodes
"""
import socket
import threading
import json
import time
import sys
import random
from collections import defaultdict
from typing import Dict, Any, Optional, Tuple

# crypto
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

HOST = "127.0.0.1"

PROTO_PORTS = [7000 + i for i in range(7)]
ADMIN_PORTS = [17000 + i for i in range(7)]
N = len(PROTO_PORTS)
F = (N - 1) // 3  # F = 2
QUORUM_2F1 = 2 * F + 1  # 2f+1 = 5

SEND_TIMEOUT = 2.0

# Global storage for public keys (used after RESET_STATE)
GLOBAL_PUBLIC_KEYS = {}

def log(*a, **kw):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, **kw)

# --- crypto helpers ---
def new_ed25519_keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def sign_msg(sk, payload: dict) -> str:
    p = {k: payload[k] for k in sorted(payload.keys()) if k != "sig"}
    raw = json.dumps(p, sort_keys=True, separators=(',', ':')).encode()
    sig = sk.sign(raw)
    return sig.hex()

def corrupt_signature(sig_hex: str, mode: int = 1) -> str:
    """Corrupt a signature in various ways for Byzantine testing"""
    if mode == 1:
        return ''.join(random.choice('0123456789abcdef') for _ in range(32))
    elif mode == 2:
        return ""
    else:
        if not sig_hex:
            return "corrupted"
        sig_bytes = bytearray.fromhex(sig_hex)
        for i in range(min(8, len(sig_bytes))):
            sig_bytes[i] ^= 0xFF
        return sig_bytes.hex()

def verify_sig(pk, payload: dict, sig_hex: str) -> bool:
    """Verify signature - returns True only if signature is cryptographically valid"""
    if not sig_hex or len(sig_hex) < 32:
        return False
    
    p = {k: payload[k] for k in sorted(payload.keys()) if k != "sig"}
    raw = json.dumps(p, sort_keys=True, separators=(',', ':')).encode()
    
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if len(sig_bytes) != 64:
            return False
        pk.verify(sig_bytes, raw)
        return True
    except (ValueError, InvalidSignature, Exception):
        return False

# --- socket helpers ---
def send_and_receive(host, port, msg: dict, timeout=SEND_TIMEOUT, expect_reply=True):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((json.dumps(msg) + "\n").encode())
            if not expect_reply:
                return None
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    return None
                buf += chunk
                if b"\n" in buf:
                    line, _, _ = buf.partition(b"\n")
                    try:
                        return json.loads(line.decode())
                    except:
                        return None
    except:
        return None

def send_to_client(client_sock, msg: dict):
    """Send message back through client's socket connection"""
    try:
        client_sock.sendall((json.dumps(msg) + "\n").encode())
    except:
        pass

class SmallBankHandler:
    """
    Handler for SmallBank transactions in PBFT
    
    Manages three tables: customers, savings, checking
    Implements six transaction types as per SmallBank spec
    """
    
    def __init__(self):
        # Three SmallBank tables
        self.customers = {}    # customer_id -> name
        self.savings = {}      # customer_id -> balance
        self.checking = {}     # customer_id -> balance
        
        # Statistics
        self.txn_counts = defaultdict(int)
        self.txn_latencies = defaultdict(list)
        self.total_executed = 0
        self.total_failed = 0
        
        print("[SmallBank] Handler initialized")
    
    def initialize_accounts(self, num_accounts: int, initial_balance: int = 10000):
        """Initialize SmallBank accounts"""
        for i in range(num_accounts):
            customer_id = f"C{i:06d}"
            self.customers[customer_id] = f"Customer_{i}"
            self.savings[customer_id] = initial_balance
            self.checking[customer_id] = initial_balance
        
        print(f"[SmallBank] Initialized {num_accounts} accounts with balance {initial_balance}")
    
    def execute_transaction(self, txn: Any, legacy_db: Dict[str, int]) -> Optional[str]:
        """
        Execute a SmallBank transaction
        
        Args:
            txn: Transaction tuple (either legacy or SmallBank format)
            legacy_db: The existing PBFT database (for backward compatibility)
        
        Returns:
            None if not a SmallBank transaction (use legacy logic)
            "success" or error message if SmallBank transaction
        """
        # Check if this is a SmallBank transaction
        if not isinstance(txn, (list, tuple)) or len(txn) != 3:
            return None
        
        if txn[0] != "SMALLBANK":
            return None
        
        # Parse SmallBank transaction
        try:
            txn_data = json.loads(txn[1])
            txn_type = txn[2]
        except (json.JSONDecodeError, IndexError):
            self.total_failed += 1
            return "parse-error"
        
        # Execute based on type
        start_time = time.time()
        result = None
        
        try:
            if txn_type == 'BALANCE':
                result = self._execute_balance(txn_data)
            elif txn_type == 'DEPOSIT_CHECKING':
                result = self._execute_deposit_checking(txn_data)
            elif txn_type == 'TRANSACT_SAVINGS':
                result = self._execute_transact_savings(txn_data)
            elif txn_type == 'AMALGAMATE':
                result = self._execute_amalgamate(txn_data)
            elif txn_type == 'WRITE_CHECK':
                result = self._execute_write_check(txn_data)
            elif txn_type == 'SEND_PAYMENT':
                result = self._execute_send_payment(txn_data)
            else:
                result = "unknown-txn-type"
        except Exception as e:
            result = f"error: {str(e)}"
        
        # Record statistics
        latency = (time.time() - start_time) * 1000  # ms
        self.txn_counts[txn_type] += 1
        self.txn_latencies[txn_type].append(latency)
        
        if result == "success":
            self.total_executed += 1
        else:
            self.total_failed += 1
        
        return result
    
    def _execute_balance(self, txn_data: Dict[str, Any]) -> str:
        """
        BALANCE: Read checking + savings balance
        """
        account = txn_data.get('account')
        
        if account not in self.customers:
            return "account-not-found"
        
        checking_balance = self.checking.get(account, 0)
        savings_balance = self.savings.get(account, 0)
        total = checking_balance + savings_balance
        
        # Read-only transaction
        return "success"
    
    def _execute_deposit_checking(self, txn_data: Dict[str, Any]) -> str:
        """
        DEPOSIT_CHECKING: Deposit amount into checking account
        """
        account = txn_data.get('account')
        amount = txn_data.get('amount', 0)
        
        if account not in self.customers:
            return "account-not-found"
        
        if amount <= 0:
            return "invalid-amount"
        
        self.checking[account] = self.checking.get(account, 0) + amount
        return "success"
    
    def _execute_transact_savings(self, txn_data: Dict[str, Any]) -> str:
        """
        TRANSACT_SAVINGS: Add or subtract from savings
        """
        account = txn_data.get('account')
        amount = txn_data.get('amount', 0)
        
        if account not in self.customers:
            return "account-not-found"
        
        current_balance = self.savings.get(account, 0)
        new_balance = current_balance + amount
        
        if new_balance < 0:
            return "insufficient-funds"
        
        self.savings[account] = new_balance
        return "success"
    
    def _execute_amalgamate(self, txn_data: Dict[str, Any]) -> str:
        """
        AMALGAMATE: Transfer all savings to checking (single account)
        """
        account = txn_data.get('account')
        
        if account not in self.customers:
            return "account-not-found"
        
        savings_balance = self.savings.get(account, 0)
        
        # Transfer savings to checking
        self.checking[account] = self.checking.get(account, 0) + savings_balance
        self.savings[account] = 0
        
        return "success"
    
    def _execute_write_check(self, txn_data: Dict[str, Any]) -> str:
        """
        WRITE_CHECK: Write check (deduct from checking)
        """
        account = txn_data.get('account')
        amount = txn_data.get('amount', 0)
        
        if account not in self.customers:
            return "account-not-found"
        
        if amount <= 0:
            return "invalid-amount"
        
        current_balance = self.checking.get(account, 0)
        
        if current_balance < amount:
            return "insufficient-funds"
        
        self.checking[account] = current_balance - amount
        return "success"
    
    def _execute_send_payment(self, txn_data: Dict[str, Any]) -> str:
        """
        SEND_PAYMENT: Transfer checking balance between two accounts
        """
        from_account = txn_data.get('from_account')
        to_account = txn_data.get('to_account')
        amount = txn_data.get('amount', 0)
        
        if from_account not in self.customers:
            return "from-account-not-found"
        
        if to_account not in self.customers:
            return "to-account-not-found"
        
        if amount <= 0:
            return "invalid-amount"
        
        from_balance = self.checking.get(from_account, 0)
        
        if from_balance < amount:
            return "insufficient-funds"
        
        # Execute transfer
        self.checking[from_account] = from_balance - amount
        self.checking[to_account] = self.checking.get(to_account, 0) + amount
        
        return "success"
    
    def get_statistics(self) -> str:
        """Get SmallBank execution statistics"""
        stats = {
            "total_executed": self.total_executed,
            "total_failed": self.total_failed,
            "success_rate": (self.total_executed / (self.total_executed + self.total_failed) * 100) 
                           if (self.total_executed + self.total_failed) > 0 else 0,
            "transaction_counts": dict(self.txn_counts),
            "num_customers": len(self.customers),
            "total_savings": sum(self.savings.values()),
            "total_checking": sum(self.checking.values())
        }
        return json.dumps(stats, indent=2)
    
    def reset(self):
        """Reset SmallBank state"""
        self.customers.clear()
        self.savings.clear()
        self.checking.clear()
        self.txn_counts.clear()
        self.txn_latencies.clear()
        self.total_executed = 0
        self.total_failed = 0
    
    def get_account_info(self, customer_id: str) -> Optional[Dict[str, Any]]:
        """Get account information"""
        if customer_id not in self.customers:
            return None
        
        return {
            "customer_id": customer_id,
            "name": self.customers[customer_id],
            "checking_balance": self.checking.get(customer_id, 0),
            "savings_balance": self.savings.get(customer_id, 0),
            "total_balance": self.checking.get(customer_id, 0) + self.savings.get(customer_id, 0)
        }

# --- Replica class ---
class ReplicaNode:
    def __init__(self, proto_port, admin_port, all_proto_ports=PROTO_PORTS, all_admin_ports=ADMIN_PORTS):
        self.proto_port = proto_port
        self.admin_port = admin_port
        self.node_index = all_proto_ports.index(proto_port)
        self.peers = [p for p in all_proto_ports if p != proto_port]
        self.admin_peers = [p for p in all_admin_ports if p != admin_port]

        # crypto keys
        self.sk, self.pk = new_ed25519_keypair()
        self.public_keys = {}

        # PBFT state
        self.view = 0
        self.is_primary = False
        self.seq_number = 0
        self.low_water_mark = 0
        self.high_water_mark = 10000

        # logs
        self.log = {}
        self.commit_index = 0
        self.last_executed = 0

        # application state (bank accounts A..J)
        self.db = {chr(ord('A') + i): 10 for i in range(10)}

        # control
        self.operational = True
        self.pause_timers = False
        
        # Byzantine behavior modes
        self.malicious_modes = {
            'invalid_signature': False,
            'crash': False,
            'timing': False,
            'dark': False,
            'equivocation': False
        }
        
        # Timing attack configuration
        self.timing_delay_ms = 500
        self.timing_delay_variance = 0.3

        # Dark attack configuration
        self.dark_nodes = set()
        
        # Equivocation attack configuration
        self.equivocation_nodes = set()  # Nodes that get alternate sequence numbers
        self.equivocation_seq_offset = 0  # Track sequence number offset for equivocated nodes

        # quorum tracking
        self.prepare_quorum = defaultdict(set)
        self.commit_quorum = defaultdict(set)
        self.prepared_certs = {}
        self.committed_certs = {}

        # checkpointing state
        self.checkpoint_interval = 3
        self.checkpoints = {}
        self.stable_checkpoint = 0
        self.checkpoint_votes = defaultdict(set)

        # view-change state
        self.view_change_log = []
        self.new_view_messages = []
        self.view_change_timer = None
        self.view_change_timeout = 5.0
        self.last_progress_time = time.time()
        self.view_change_votes = defaultdict(set)
        self.in_view_change = False
        
        # Primary liveness tracking
        self.last_request_time = None
        self.primary_timeout = 4.0
        self.pending_requests = {}

        # client connection tracking
        self.pending_clients = {}

        # threading
        self.lock = threading.RLock()
        self.running = True

        # SmallBank support
        self.smallbank = SmallBankHandler()
        self.smallbank.initialize_accounts(num_accounts=100, initial_balance=10000)

    def _should_send_to_node(self, target_node_idx: int) -> bool:
        '''Check if we should send messages to target node (dark attack filter)'''
        if not self.malicious_modes.get('dark'):
            return True
        
        # If in dark mode, exclude nodes in dark_nodes set
        if target_node_idx in self.dark_nodes:
            log(f"[R{self.node_index}] [BYZANTINE-DARK] Suppressing message to R{target_node_idx} (in-dark)")
            return False
        
        return True

    def _apply_timing_delay(self, context: str = ""):
        """Apply timing attack delay with variance"""
        if not self.malicious_modes.get('timing'):
            return
        
        # Calculate delay with random variance
        base_delay = self.timing_delay_ms / 1000.0
        variance = base_delay * self.timing_delay_variance
        actual_delay = base_delay + random.uniform(-variance, variance)
        
        # Ensure delay is positive and within bounds
        actual_delay = max(0.1, min(actual_delay, self.primary_timeout * 0.3))
        
        log(f"[R{self.node_index}] [BYZANTINE-TIMING] Delaying {context} by {actual_delay:.2f}s")
        time.sleep(actual_delay)

    def _is_equivocation_node(self, target_node_idx: int) -> bool:
        """Check if target node should receive equivocated sequence number"""
        return (self.malicious_modes.get('equivocation') and 
                target_node_idx in self.equivocation_nodes)

    def register_public_keys(self, all_nodes):
        for idx, pk_obj in all_nodes.items():
            self.public_keys[idx] = pk_obj

    def my_pub_bytes(self):
        return self.pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()

    def start(self):
        threading.Thread(target=self._protocol_server, daemon=True).start()
        threading.Thread(target=self._admin_server, daemon=True).start()
        self.start_view_change_timer()
        log(f"Replica[{self.node_index}] started proto={self.proto_port} admin={self.admin_port}")

    def stop(self):
        self.running = False

    def start_view_change_timer(self):
        with self.lock:
            self.last_progress_time = time.time()
            if self.view_change_timer is None and not self.pause_timers:
                self.view_change_timer = threading.Thread(
                    target=self._view_change_timer_thread, 
                    daemon=True
                )
                self.view_change_timer.start()

    def _view_change_timer_thread(self):
        while self.running:
            time.sleep(0.5)
            
            with self.lock:
                if self.pause_timers or not self.operational:
                    continue
                
                # Check if we're a backup and haven't heard from primary about pending requests
                if not self.is_primary and self.pending_requests:
                    current_time = time.time()
                    
                    for digest, req_time in list(self.pending_requests.items()):
                        time_waiting = current_time - req_time
                        
                        if time_waiting > self.primary_timeout and not self.in_view_change:
                            log(f"[R{self.node_index}] BACKUP TIMEOUT! Waited {time_waiting:.1f}s for PRE-PREPARE (digest: {digest[:16]}...)")
                            log(f"[R{self.node_index}] Primary (R{self.view % N}) appears to have CRASHED or is too slow")
                            log(f"[R{self.node_index}] Initiating VIEW-CHANGE to elect new primary")
                            self._initiate_view_change()
                            break
                
                has_pending = any(
                    not entry.get("executed") 
                    for entry in self.log.values()
                )
                
                if not has_pending:
                    self.last_progress_time = time.time()
                    continue
                
                elapsed = time.time() - self.last_progress_time
                
                if elapsed > self.view_change_timeout and not self.in_view_change:
                    log(f"[R{self.node_index}] Progress timeout! No execution for {elapsed:.1f}s. Initiating VIEW-CHANGE")
                    self._initiate_view_change()

    def reset_progress_timer(self):
        with self.lock:
            self.last_progress_time = time.time()

    def _protocol_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, self.proto_port))
        sock.listen(8)
        while self.running:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_proto_conn, args=(conn, addr), daemon=True).start()
            except:
                break
        sock.close()

    def _handle_proto_conn(self, conn, addr):
        with conn:
            try:
                with self.lock:
                    if not self.operational:
                        return
                
                data = b""
                conn.settimeout(30.0)
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                    if b"\n" in data:
                        line, _, rest = data.partition(b"\n")
                        data = rest
                        try:
                            msg = json.loads(line.decode())
                        except:
                            return
                        
                        with self.lock:
                            if not self.operational:
                                return
                        
                        msg_type = msg.get("type")
                        
                        if msg_type == "REQUEST":
                            reply = self._on_request(msg, conn)
                            if reply:
                                conn.sendall((json.dumps(reply) + "\n").encode())
                                return
                            else:
                                return
                        elif msg_type == "READ_REQUEST":
                            reply = self._on_read_request(msg)
                            if reply:
                                conn.sendall((json.dumps(reply) + "\n").encode())
                            return
                        else:
                            reply = self._process_protocol_message(msg)
                            if reply is None:
                                return
                            conn.sendall((json.dumps(reply) + "\n").encode())
                            return
            except:
                return

    def _admin_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, self.admin_port))
        sock.listen(5)
        while self.running:
            try:
                conn, _ = sock.accept()
                threading.Thread(target=self._handle_admin_conn, args=(conn,), daemon=True).start()
            except:
                break
        sock.close()

    def _handle_admin_conn(self, conn):
        with conn:
            try:
                conn.sendall(b"ADMIN-READY\n")
            except:
                return
            data = b""
            conn.settimeout(5.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                    if b"\n" in data:
                        line, _, rest = data.partition(b"\n")
                        data = rest
                        cmd = line.decode().strip()
                        out = self._process_admin_command(cmd)
                        try:
                            conn.sendall((out + "\n").encode())
                        except:
                            pass
                        return
            except:
                return

    def _process_protocol_message(self, msg: dict):
        mtype = msg.get("type")
        if not mtype:
            return {"error": "no-type"}

        if "from_node" in msg:
            from_idx = int(msg["from_node"])
            
            if "sig" not in msg or not msg["sig"]:
                log(f"[R{self.node_index}] [REJECT] Missing signature from R{from_idx} in {mtype}")
                return {"error": "missing-signature", "rejected": True}
            
            sig = msg["sig"]
            pk_hex = self.public_keys.get(from_idx)
            
            if not pk_hex:
                log(f"[R{self.node_index}] [REJECT] No public key for R{from_idx}")
                return {"error": "no-public-key", "rejected": True}
            
            try:
                raw = bytes.fromhex(pk_hex)
                pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
                
                is_valid = verify_sig(pub, msg, sig)
                
                if not is_valid:
                    log(f"[R{self.node_index}] [REJECT] Invalid signature from R{from_idx} in {mtype}")
                    return {"error": "bad-signature", "rejected": True}
                        
            except Exception as e:
                log(f"[R{self.node_index}] [REJECT] Signature verification exception from R{from_idx}: {e}")
                return {"error": "sig-verify-failed", "rejected": True}

        if mtype == "PRE-PREPARE":
            return self._on_pre_prepare(msg)
        if mtype == "PREPARE":
            return self._on_prepare(msg)
        if mtype == "COLLECT_PREPARES":
            return self._on_collect_prepares(msg)
        if mtype == "COMMIT":
            return self._on_commit(msg)
        if mtype == "COLLECT_COMMITS":
            return self._on_collect_commits(msg)
        if mtype == "CHECKPOINT":
            return self._on_checkpoint(msg)
        if mtype == "STATE_TRANSFER_REQUEST":
            return self._on_state_transfer_request(msg)
        if mtype == "STATE_TRANSFER_RESPONSE":
            return self._on_state_transfer_response(msg)
        if mtype == "VIEW-CHANGE":
            return self._on_view_change(msg)
        if mtype == "NEW-VIEW":
            return self._on_new_view(msg)

        return {"error": "unknown-type"}

    def _sign_message(self, msg: dict) -> str:
        """Sign a message, applying malicious behavior if enabled"""
        valid_sig = sign_msg(self.sk, msg)
        
        if self.malicious_modes.get('invalid_signature'):
            mode = random.randint(1, 3)
            corrupted = corrupt_signature(valid_sig, mode)
            msg_type = msg.get("type", "UNKNOWN")
            log(f"[R{self.node_index}] [BYZANTINE] Corrupting {msg_type} signature")
            return corrupted
        
        return valid_sig

    def _on_read_request(self, msg):
        with self.lock:
            if not self.operational:
                return {"error": "node-unavailable"}
            
            if self.malicious_modes.get('crash'):
                log(f"[R{self.node_index}] [BYZANTINE-CRASH] Dropping READ request (no reply)")
                return None
            
            # TIMING ATTACK: Delay read responses
            if self.malicious_modes.get('timing'):
                self._apply_timing_delay("READ response")
            
            account = msg.get("account")
            if not account:
                return {"error": "missing-account"}
            
            balance = self.db.get(account, 0)
            
            reply = {
                "type": "READ_REPLY",
                "result": "success",
                "account": account,
                "balance": balance,
                "view": self.view,
                "node": self.node_index,
                "timestamp": int(time.time() * 1000)
            }
            reply["sig"] = self._sign_message(reply)
            
            log(f"[R{self.node_index}] READ {account} = {balance}")
            return reply

    def _on_request(self, msg, client_sock):
        with self.lock:
            if not self.operational:
                return {"error": "node-unavailable"}
                
            if not self.is_primary:
                request = msg.get("request")
                timestamp = msg.get("timestamp")
                
                if request and timestamp:
                    temp_digest = self._digest(request)
                    
                    if temp_digest not in [e.get("digest") for e in self.log.values()]:
                        self.pending_requests[temp_digest] = time.time()
                        log(f"[R{self.node_index}] BACKUP: Received client request, waiting for PRE-PREPARE from primary R{self.view % N}")
                        log(f"[R{self.node_index}] BACKUP: Request digest: {temp_digest[:16]}... (timeout in {self.primary_timeout}s)")
                
                return {"result": "redirect", "view": self.view, "primary_hint": self._primary_hint()}
            
            # TIMING ATTACK: Delay before processing client request
            if self.malicious_modes.get('timing'):
                self._apply_timing_delay("client REQUEST processing")
            
            # Get base sequence number
            self.seq_number += 1
            base_seq = self.seq_number
            
            request = msg.get("request")
            digest = self._digest(request)
            client_id = msg.get("client_id")
            timestamp = msg.get("timestamp")
            
            # EQUIVOCATION ATTACK: Determine if we need alternate sequence numbers
            if self.malicious_modes.get('equivocation') and self.equivocation_nodes:
                # Use WIDELY SEPARATED sequence numbers to avoid gaps in majority execution
                # Majority gets: 1, 2, 3, 4, 5, ... (consecutive)
                # Minority gets: 10001, 10002, 10003, ... (isolated range)
                
                # Calculate alternate sequence in isolated range
                alt_seq = 10000 + base_seq
                # Don't update self.seq_number - keep majority sequence consecutive
                
                log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] Using seq={base_seq} for majority, seq={alt_seq} for nodes {sorted(self.equivocation_nodes)}")
                log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] Majority will execute consecutively, minority isolated in 10000+ range")
            else:
                alt_seq = None
            
            # Track both sequence numbers if equivocating
            self.pending_clients[base_seq] = client_sock
            if alt_seq:
                self.pending_clients[alt_seq] = client_sock
            
            # Store in log for both sequences
            log_entry = {
                "request": request,
                "digest": digest,
                "view": self.view,
                "client_id": client_id,
                "timestamp": timestamp,
                "prepares": set(),
                "commits": set(),
                "prepared": False,
                "committed": False,
                "executed": False
            }
            
            if self.malicious_modes.get('crash'):
                log(f"[R{self.node_index}] [BYZANTINE-CRASH] PRIMARY refusing to send PRE-PREPARE")
                self.log[base_seq] = log_entry.copy()
                return {"result": "queued", "seq": base_seq, "view": self.view}
            
            # TIMING ATTACK: Delay before sending PRE-PREPARE
            if self.malicious_modes.get('timing'):
                self._apply_timing_delay("PRE-PREPARE broadcast")
            
            # Send PRE-PREPARE messages (potentially different seq numbers)
            for p in self.peers:
                peer_idx = PROTO_PORTS.index(p)
                
                # Dark attack: Skip nodes that are in-dark
                if not self._should_send_to_node(peer_idx):
                    log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING PRE-PREPARE to R{peer_idx} (excluded)")
                    continue
                
                # EQUIVOCATION: Choose sequence number based on target node
                if alt_seq and self._is_equivocation_node(peer_idx):
                    seq = alt_seq
                    log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] Sending seq={seq} to R{peer_idx}")
                else:
                    seq = base_seq
                
                # Create PRE-PREPARE with appropriate sequence number
                pp = {
                    "type": "PRE-PREPARE",
                    "view": self.view,
                    "seq": seq,
                    "digest": digest,
                    "request": request,
                    "client_id": client_id,
                    "timestamp": timestamp,
                    "from_node": self.node_index
                }
                pp["sig"] = self._sign_message(pp)
                
                # Store preprepare in log
                if seq not in self.log:
                    self.log[seq] = log_entry.copy()
                self.log[seq]["preprepare"] = pp
                
                threading.Thread(target=send_and_receive, args=(HOST, p, pp, SEND_TIMEOUT, False), daemon=True).start()
            
            # Primary also sends PREPARE to itself (for base sequence)
            prepare = {
                "type": "PREPARE",
                "view": self.view,
                "seq": base_seq,
                "digest": digest,
                "from_node": self.node_index
            }
            prepare["sig"] = self._sign_message(prepare)
            
            # Store base sequence in log
            if base_seq not in self.log:
                self.log[base_seq] = log_entry.copy()
            self.log[base_seq]["preprepare"] = {
                "type": "PRE-PREPARE",
                "view": self.view,
                "seq": base_seq,
                "digest": digest,
                "request": request,
                "client_id": client_id,
                "timestamp": timestamp,
                "from_node": self.node_index
            }
            
            threading.Thread(target=send_and_receive, args=(HOST, self.proto_port, prepare, SEND_TIMEOUT, False), daemon=True).start()
            
            self.reset_progress_timer()
            
            if alt_seq:
                log(f"[R{self.node_index}] PRIMARY assigned seq={base_seq} (majority) and seq={alt_seq} (equivocated) for {request}")
            else:
                log(f"[R{self.node_index}] PRIMARY assigned seq={base_seq} for {request}")
            
            return {"result": "queued", "seq": base_seq, "view": self.view}

    def _on_pre_prepare(self, msg):
        with self.lock:
            if not self.operational:
                return {"error": "node-unavailable"}
            
            # TIMING ATTACK: Delay processing PRE-PREPARE (backup behavior)
            if self.malicious_modes.get('timing') and not self.is_primary:
                self._apply_timing_delay("PRE-PREPARE processing")
                
            view = msg.get("view")
            seq = int(msg.get("seq"))
            digest = msg.get("digest")
            request = msg.get("request")
            
            if view != self.view:
                return {"error": "wrong-view"}
            
            if digest != self._digest(request):
                return {"error": "bad-digest"}
            
            if digest in self.pending_requests:
                wait_time = time.time() - self.pending_requests[digest]
                log(f"[R{self.node_index}] Received PRE-PREPARE seq={seq} for pending request (waited {wait_time:.2f}s)")
                del self.pending_requests[digest]
            
            self.log.setdefault(seq, {})
            self.log[seq].update({
                "request": request,
                "digest": digest,
                "view": view,
                "client_id": msg.get("client_id"),
                "timestamp": msg.get("timestamp"),
                "preprepare": msg,
                "prepares": set(),
                "commits": set(),
                "prepared": False,
                "committed": False,
                "executed": False
            })
            
            log(f"[R{self.node_index}] Received PRE-PREPARE seq={seq}")
            
            if self.malicious_modes.get('crash'):
                log(f"[R{self.node_index}] [BYZANTINE-CRASH] BACKUP refusing to send PREPARE")
                return {"ok": True}
            
            # TIMING ATTACK: Delay sending PREPARE (backup behavior)
            if self.malicious_modes.get('timing') and not self.is_primary:
                self._apply_timing_delay("PREPARE sending")
            
            prepare = {
                "type": "PREPARE",
                "view": self.view,
                "seq": seq,
                "digest": digest,
                "from_node": self.node_index
            }
            prepare["sig"] = self._sign_message(prepare)
            
            primary_idx = self.view % N
            primary_port = PROTO_PORTS[primary_idx]
            if not self._should_send_to_node(primary_idx):
                log(f"[R{self.node_index}] [BYZANTINE-DARK] Not sending PREPARE to primary R{primary_idx}")
                return {"ok": True}
            threading.Thread(target=send_and_receive, args=(HOST, primary_port, prepare, SEND_TIMEOUT, False), daemon=True).start()
            
            self.reset_progress_timer()
            return {"ok": True}

    def _on_prepare(self, msg):
        view = msg.get("view")
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        from_node = int(msg.get("from_node", -1))
        
        key = (view, seq, digest)
        
        with self.lock:
            if not self.is_primary:
                return {"ok": True}
            
            self.prepare_quorum[key].add(from_node)
            
            if seq in self.log:
                self.log[seq]["prepares"].add(from_node)
            
            log(f"[R{self.node_index}] ✓ PREPARE from R{from_node}, seq={seq}, count={len(self.prepare_quorum[key])}/{QUORUM_2F1}")
            
            if self.malicious_modes.get('crash'):
                if len(self.prepare_quorum[key]) >= QUORUM_2F1:
                    log(f"[R{self.node_index}] [BYZANTINE-CRASH] PRIMARY has quorum but refusing to send COLLECT_PREPARES")
                return {"ok": True}
            
            if len(self.prepare_quorum[key]) >= QUORUM_2F1:
                if seq not in self.prepared_certs:
                    self.prepared_certs[seq] = True
                    
                    # TIMING ATTACK: Delay before broadcasting COLLECT_PREPARES
                    if self.malicious_modes.get('timing'):
                        self._apply_timing_delay("COLLECT_PREPARES broadcast")
                    
                    coll = {
                        "type": "COLLECT_PREPARES",
                        "view": view,
                        "seq": seq,
                        "digest": digest,
                        "members": list(self.prepare_quorum[key]),
                        "from_node": self.node_index
                    }
                    coll["sig"] = self._sign_message(coll)
                    
                    log(f"[R{self.node_index}] COLLECTOR broadcasting COLLECT_PREPARES seq={seq}")
                    
                    # Dark and Equivocation attacks: Filter recipients
                    for p in PROTO_PORTS:
                        peer_idx = PROTO_PORTS.index(p)
                        
                        # Dark attack: Skip dark nodes
                        if not self._should_send_to_node(peer_idx):
                            log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING COLLECT_PREPARES to R{peer_idx} (excluded)")
                            continue
                        
                        # EQUIVOCATION: Don't send COLLECT_PREPARES for base_seq to equivocated nodes
                        # (they're waiting for their alternate sequence number)
                        if (self.malicious_modes.get('equivocation') and 
                            self._is_equivocation_node(peer_idx)):
                            log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] SKIPPING COLLECT_PREPARES seq={seq} to R{peer_idx} (waiting for alternate seq)")
                            continue
                        
                        threading.Thread(target=send_and_receive, args=(HOST, p, coll, SEND_TIMEOUT, False), daemon=True).start()
        
        return {"ok": True}

    def _on_collect_prepares(self, msg):
        view = msg.get("view")
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        members = msg.get("members", [])
        
        with self.lock:
            if len(members) < QUORUM_2F1:
                return {"error": "insufficient-quorum"}
            
            if self.malicious_modes.get('crash'):
                log(f"[R{self.node_index}] [BYZANTINE-CRASH] Refusing to mark seq={seq} as PREPARED")
                return {"ok": True}
            
            if seq in self.log:
                self.log[seq]["prepared"] = True
            
            log(f"[R{self.node_index}] PREPARED seq={seq} (certificate with {len(members)} prepares)")
            
            commit = {
                "type": "COMMIT",
                "view": self.view,
                "seq": seq,
                "digest": digest,
                "from_node": self.node_index
            }
            commit["sig"] = self._sign_message(commit)
            
            primary_idx = self.view % N
            primary_port = PROTO_PORTS[primary_idx]

            if self.malicious_modes.get('dark') and not self._should_send_to_node(primary_idx):
                log(f"[R{self.node_index}] [BYZANTINE-DARK] Not sending COMMIT to primary R{primary_idx}")
                return {"ok": True}
            
            if seq in self.log:
                self.log[seq]["commits"].add(self.node_index)
            
            threading.Thread(target=send_and_receive, args=(HOST, primary_port, commit, SEND_TIMEOUT, False), daemon=True).start()
        
        return {"ok": True}

    def _on_commit(self, msg):
        view = msg.get("view")
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        from_node = int(msg.get("from_node", -1))
        
        key = (view, seq, digest)
        
        with self.lock:
            if not self.is_primary:
                return {"ok": True}
            
            self.commit_quorum[key].add(from_node)
            
            if seq in self.log:
                self.log[seq]["commits"].add(from_node)
            
            log(f"[R{self.node_index}] COMMIT from R{from_node}, seq={seq}, count={len(self.commit_quorum[key])}/{QUORUM_2F1}")
            
            if len(self.commit_quorum[key]) >= QUORUM_2F1:
                if seq not in self.committed_certs:
                    self.committed_certs[seq] = True
                    
                    # TIMING ATTACK: Delay before broadcasting COLLECT_COMMITS
                    if self.malicious_modes.get('timing'):
                        self._apply_timing_delay("COLLECT_COMMITS broadcast")
                    
                    coll = {
                        "type": "COLLECT_COMMITS",
                        "view": view,
                        "seq": seq,
                        "digest": digest,
                        "members": list(self.commit_quorum[key]),
                        "from_node": self.node_index
                    }
                    coll["sig"] = self._sign_message(coll)
                    
                    log(f"[R{self.node_index}] COLLECTOR broadcasting COLLECT_COMMITS seq={seq}")
                    
                    # Dark and Equivocation attacks: Filter recipients
                    for p in PROTO_PORTS:
                        peer_idx = PROTO_PORTS.index(p)
                        
                        # Dark attack: Skip dark nodes
                        if not self._should_send_to_node(peer_idx):
                            log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING COLLECT_COMMITS to R{peer_idx} (excluded)")
                            continue
                        
                        # EQUIVOCATION: Similar to COLLECT_PREPARES
                        if (self.malicious_modes.get('equivocation') and 
                            self._is_equivocation_node(peer_idx)):
                            log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] SKIPPING COLLECT_COMMITS seq={seq} to R{peer_idx}")
                            continue
                        
                        threading.Thread(target=send_and_receive, args=(HOST, p, coll, SEND_TIMEOUT, False), daemon=True).start()
        
        return {"ok": True}

    def _on_collect_commits(self, msg):
        view = msg.get("view")
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        members = msg.get("members", [])
        
        with self.lock:
            if len(members) < QUORUM_2F1:
                return {"error": "insufficient-quorum"}
            
            if seq in self.log:
                self.log[seq]["committed"] = True
            
            log(f"[R{self.node_index}] COMMITTED seq={seq} (certificate with {len(members)} commits)")
            
            next_seq = self.last_executed + 1
            while next_seq in self.log and self.log[next_seq].get("committed"):
                self._execute_up_to(next_seq)
                next_seq += 1
            
            self.reset_progress_timer()
        
        return {"ok": True}

    def _initiate_view_change(self):
        with self.lock:
            if self.in_view_change:
                return
            
            self.in_view_change = True
            new_view = self.view + 1
            
            prepared_proofs = []
            for seq, entry in self.log.items():
                if entry.get("prepared") and not entry.get("executed"):
                    prepared_proofs.append({
                        "seq": seq,
                        "digest": entry.get("digest"),
                        "view": entry.get("view")
                    })
            
            stable_checkpoint_cert = None
            if self.stable_checkpoint > 0 and self.stable_checkpoint in self.checkpoints:
                ckpt = self.checkpoints[self.stable_checkpoint]
                stable_checkpoint_cert = {
                    "seq": self.stable_checkpoint,
                    "digest": ckpt["digest"],
                    "certificates": ckpt["certificates"]
                }
            
            vc_msg = {
                "type": "VIEW-CHANGE",
                "new_view": new_view,
                "from_node": self.node_index,
                "prepared": prepared_proofs,
                "last_executed": self.last_executed,
                "stable_checkpoint": stable_checkpoint_cert
            }
            vc_msg["sig"] = self._sign_message(vc_msg)
            
            log(f"[R{self.node_index}] Sending VIEW-CHANGE for view {new_view}")
            
            # Dark attack: Filter recipients
            for p in PROTO_PORTS:
                peer_idx = PROTO_PORTS.index(p)
                if not self._should_send_to_node(peer_idx):
                    log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING VIEW-CHANGE to R{peer_idx} (excluded)")
                    continue
                threading.Thread(
                    target=send_and_receive, 
                    args=(HOST, p, vc_msg, SEND_TIMEOUT, False), 
                    daemon=True
                ).start()

    def _on_view_change(self, msg):
        new_view = msg.get("new_view")
        from_node = int(msg.get("from_node", -1))
        
        with self.lock:
            self.view_change_log.append(msg)
            self.view_change_votes[new_view].add(from_node)
            
            log(f"[R{self.node_index}] Received VIEW-CHANGE from R{from_node} for view {new_view}")
            
            new_primary_idx = new_view % N
            
            if (new_primary_idx == self.node_index and 
                len(self.view_change_votes[new_view]) >= QUORUM_2F1):
                
                log(f"[R{self.node_index}] Received quorum of VIEW-CHANGE, becoming primary for view {new_view}")
                
                self._send_new_view(new_view)
        
        return {"ok": True}

    def _send_new_view(self, new_view):
        with self.lock:
            if self.malicious_modes.get('crash'):
                log(f"[R{self.node_index}] [BYZANTINE-CRASH] PRIMARY refusing to send NEW-VIEW for view {new_view}")
                self.view = new_view
                self.is_primary = True
                self.in_view_change = False
                self.last_progress_time = time.time()
                return
            
            # TIMING ATTACK: Delay before sending NEW-VIEW
            if self.malicious_modes.get('timing'):
                self._apply_timing_delay("NEW-VIEW broadcast")
            
            vc_messages = [vc for vc in self.view_change_log 
                           if vc.get("new_view") == new_view]
            
            max_stable_ckpt = 0
            for vc in vc_messages:
                ckpt = vc.get("stable_checkpoint")
                if ckpt:
                    max_stable_ckpt = max(max_stable_ckpt, ckpt.get("seq", 0))
            
            max_executed = max([vc.get("last_executed", 0) for vc in vc_messages])
            start_seq = max(max_stable_ckpt, max_executed)
            
            preprepares = []
            for seq, entry in self.log.items():
                if seq > start_seq and not entry.get("executed"):
                    pp = {
                        "view": new_view,
                        "seq": seq,
                        "digest": entry.get("digest"),
                        "request": entry.get("request")
                    }
                    preprepares.append(pp)
            
            nv_msg = {
                "type": "NEW-VIEW",
                "view": new_view,
                "view_changes": vc_messages,
                "preprepares": preprepares,
                "from_node": self.node_index
            }
            nv_msg["sig"] = self._sign_message(nv_msg)
            
            log(f"[R{self.node_index}] Sending NEW-VIEW for view {new_view}")
            
            # Dark attack: Filter recipients
            for p in PROTO_PORTS:
                peer_idx = PROTO_PORTS.index(p)
                if not self._should_send_to_node(peer_idx):
                    log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING NEW-VIEW to R{peer_idx} (excluded)")
                    continue
                threading.Thread(
                    target=send_and_receive,
                    args=(HOST, p, nv_msg, SEND_TIMEOUT, False),
                    daemon=True
                ).start()
            
            self.view = new_view
            self.is_primary = True
            self.in_view_change = False
            self.last_progress_time = time.time()
            
            log(f"[R{self.node_index}] Now PRIMARY for view {new_view}")

    def _on_new_view(self, msg):
        new_view = msg.get("view")
        from_node = int(msg.get("from_node", -1))
        vc_messages = msg.get("view_changes", [])
        preprepares = msg.get("preprepares", [])
        
        with self.lock:
            expected_primary = new_view % N
            if from_node != expected_primary:
                return {"error": "wrong-primary"}
            
            if len(vc_messages) < QUORUM_2F1:
                return {"error": "insufficient-view-changes"}
            
            log(f"[R{self.node_index}] Accepting NEW-VIEW for view {new_view}")
            
            self.view = new_view
            self.is_primary = (self.node_index == expected_primary)
            self.in_view_change = False
            self.last_progress_time = time.time()
            self.new_view_messages.append(msg)
            
            for pp in preprepares:
                seq = pp.get("seq")
                if seq not in self.log or not self.log[seq].get("executed"):
                    self.log.setdefault(seq, {})
                    self.log[seq].update({
                        "request": pp.get("request"),
                        "digest": pp.get("digest"),
                        "view": new_view,
                        "preprepare": pp,
                        "prepares": set(),
                        "commits": set(),
                        "prepared": False,
                        "committed": False,
                        "executed": False
                    })
            
            log(f"[R{self.node_index}] View change complete, primary={'YES' if self.is_primary else 'NO'}")
        
        return {"ok": True}

    def _execute_up_to(self, seq):
        with self.lock:
            ent = self.log.get(seq)
            if ent is None or ent.get("executed"):
                return
            
            txn = ent.get("request")
            result = None
            
            result = self.smallbank.execute_transaction(txn, self.db)
            if result is None:
                # Not a SmallBank transaction, use legacy logic
                if isinstance(txn, (list, tuple)) and len(txn) == 3:
                    sender, recv, amt = txn[0], txn[1], int(txn[2])
                    if self.db.get(sender, 0) >= amt:
                        self.db[sender] -= amt
                        self.db[recv] = self.db.get(recv, 0) + amt
                        result = "success"
                        log(f"[R{self.node_index}] EXECUTED seq={seq}: {sender}→{recv} {amt} units")
                    else:
                        result = "insufficient-funds"
                        log(f"[R{self.node_index}] EXECUTED seq={seq}: FAILED (insufficient funds)")
                else:
                    result = "noop"
            else:
                # SmallBank transaction executed
                log(f"[R{self.node_index}] EXECUTED SmallBank seq={seq}: {result}")
            
            ent["executed"] = True
            ent["result"] = result
            self.last_executed = seq
            
            if self.is_primary:
                self._send_reply(seq, ent)
            
            if seq % self.checkpoint_interval == 0:
                self._create_checkpoint(seq)
            
            self.commit_index = max(self.commit_index, seq)

    def _send_reply(self, seq, log_entry):
        if self.malicious_modes.get('crash'):
            log(f"[R{self.node_index}] [BYZANTINE-CRASH] Refusing to send REPLY to client for seq={seq}")
            client_sock = self.pending_clients.get(seq)
            if client_sock:
                try:
                    client_sock.close()
                except:
                    pass
                finally:
                    if seq in self.pending_clients:
                        del self.pending_clients[seq]
            return
        
        # TIMING ATTACK: Delay before sending REPLY to client
        if self.malicious_modes.get('timing'):
            self._apply_timing_delay("REPLY to client")
        
        client_id = log_entry.get("client_id")
        timestamp = log_entry.get("timestamp")
        result = log_entry.get("result")
        
        reply = {
            "type": "REPLY",
            "view": self.view,
            "timestamp": timestamp,
            "client_id": client_id,
            "result": result,
            "replica": self.node_index,
            "seq": seq
        }
        reply["sig"] = self._sign_message(reply)
        
        log(f"[R{self.node_index}] Sending REPLY to client: {result}")
        
        client_sock = self.pending_clients.get(seq)
        if client_sock:
            try:
                send_to_client(client_sock, reply)
                client_sock.close()
            except:
                pass
            finally:
                if seq in self.pending_clients:
                    del self.pending_clients[seq]

    def _create_checkpoint(self, seq):
        with self.lock:
            state_digest = self._digest(self.db)
            
            self.checkpoints[seq] = {
                "seq": seq,
                "digest": state_digest,
                "state_snapshot": dict(self.db),
                "certificates": [],
                "stable": False
            }
            
            log(f"[R{self.node_index}] CHECKPOINT created at seq={seq}")
            
            ckpt_msg = {
                "type": "CHECKPOINT",
                "seq": seq,
                "digest": state_digest,
                "from_node": self.node_index
            }
            ckpt_msg["sig"] = self._sign_message(ckpt_msg)
            
            # Dark attack: Filter recipients
            for p in PROTO_PORTS:
                peer_idx = PROTO_PORTS.index(p)
                if not self._should_send_to_node(peer_idx):
                    log(f"[R{self.node_index}] [BYZANTINE-DARK] SKIPPING CHECKPOINT to R{peer_idx} (excluded)")
                    continue
                threading.Thread(
                    target=send_and_receive,
                    args=(HOST, p, ckpt_msg, SEND_TIMEOUT, False),
                    daemon=True
                ).start()

    def _on_checkpoint(self, msg):
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        from_node = int(msg.get("from_node", -1))
        
        key = (seq, digest)
        
        with self.lock:
            self.checkpoint_votes[key].add(from_node)
            
            if seq not in self.checkpoints:
                self.checkpoints[seq] = {
                    "seq": seq,
                    "digest": digest,
                    "state_snapshot": None,
                    "certificates": [],
                    "stable": False
                }
            
            self.checkpoints[seq]["certificates"].append(msg)
            
            vote_count = len(self.checkpoint_votes[key])
            log(f"[R{self.node_index}] CHECKPOINT vote from R{from_node}, seq={seq}, count={vote_count}/{QUORUM_2F1}")
            
            if vote_count >= QUORUM_2F1 and not self.checkpoints[seq]["stable"]:
                self.checkpoints[seq]["stable"] = True
                self.stable_checkpoint = max(self.stable_checkpoint, seq)
                log(f"[R{self.node_index}] [OK] STABLE CHECKPOINT at seq={seq}")
                
                if self.last_executed < seq:
                    log(f"[R{self.node_index}] Behind stable checkpoint, requesting state transfer")
                    self._request_state_transfer(seq)
        
        return {"ok": True}

    def _request_state_transfer(self, target_seq):
        with self.lock:
            request = {
                "type": "STATE_TRANSFER_REQUEST",
                "target_seq": target_seq,
                "from_node": self.node_index
            }
            request["sig"] = self._sign_message(request)
            
            log(f"[R{self.node_index}] Requesting state transfer for seq={target_seq}")
            
            if self.peers:
                target_port = random.choice(self.peers)
                threading.Thread(
                    target=send_and_receive,
                    args=(HOST, target_port, request, SEND_TIMEOUT, False),
                    daemon=True
                ).start()

    def _on_state_transfer_request(self, msg):
        target_seq = int(msg.get("target_seq"))
        from_node = int(msg.get("from_node", -1))
        
        with self.lock:
            if target_seq in self.checkpoints and self.checkpoints[target_seq].get("stable"):
                ckpt = self.checkpoints[target_seq]
                
                response = {
                    "type": "STATE_TRANSFER_RESPONSE",
                    "seq": target_seq,
                    "digest": ckpt["digest"],
                    "state_snapshot": ckpt["state_snapshot"],
                    "certificates": ckpt["certificates"],
                    "from_node": self.node_index
                }
                response["sig"] = self._sign_message(response)
                
                log(f"[R{self.node_index}] Sending state transfer to R{from_node}")
                
                target_port = PROTO_PORTS[from_node]
                threading.Thread(
                    target=send_and_receive,
                    args=(HOST, target_port, response, SEND_TIMEOUT, False),
                    daemon=True
                ).start()
        
        return {"ok": True}

    def _on_state_transfer_response(self, msg):
        seq = int(msg.get("seq"))
        digest = msg.get("digest")
        state_snapshot = msg.get("state_snapshot")
        certificates = msg.get("certificates", [])
        from_node = int(msg.get("from_node", -1))
        
        with self.lock:
            if len(certificates) < QUORUM_2F1:
                return {"error": "insufficient-certificates"}
            
            if digest != self._digest(state_snapshot):
                return {"error": "digest-mismatch"}
            
            log(f"[R{self.node_index}] Applying state transfer from R{from_node}")
            
            self.db = dict(state_snapshot)
            self.last_executed = seq
            
            self.checkpoints[seq] = {
                "seq": seq,
                "digest": digest,
                "state_snapshot": dict(state_snapshot),
                "certificates": certificates,
                "stable": True
            }
            self.stable_checkpoint = max(self.stable_checkpoint, seq)
            
            log(f"[R{self.node_index}] [OK] State transfer complete")
        
        return {"ok": True}

    def _process_admin_command(self, cmd: str) -> str:
        c = cmd.strip().upper()
        
        if c == "SMALLBANK_STATS":
            with self.lock:
                return self.smallbank.get_statistics()
   
        if c == "SMALLBANK_RESET":
            with self.lock:
                self.smallbank.reset()
                self.smallbank.initialize_accounts(num_accounts=100, initial_balance=10000)
            return "OK"
        
        if c.startswith("SMALLBANK_INIT"):
            parts = c.split()
            num_accounts = int(parts[1]) if len(parts) >= 2 else 100
            initial_balance = int(parts[2]) if len(parts) >= 3 else 10000
            with self.lock:
                self.smallbank.reset()
                self.smallbank.initialize_accounts(num_accounts, initial_balance)
            return f"OK-{num_accounts}-{initial_balance}"
        
        if c == "STATUS":
            with self.lock:
                st = {
                    "node": self.node_index,
                    "primary": self.is_primary,
                    "view": self.view,
                    "seq": self.seq_number,
                    "operational": self.operational,
                    "last_executed": self.last_executed,
                    "in_view_change": self.in_view_change,
                    "byzantine_mode": any(self.malicious_modes.values()),
                    "public_keys_registered": len(self.public_keys)
                }
            return json.dumps(st)
        
        if c == "FAIL":
            with self.lock:
                self.operational = False
            return "OK"
        
        if c == "RECOVER":
            with self.lock:
                self.operational = True
                self.last_progress_time = time.time()
            return "OK"
        
        if c == "PRINTDB":
            with self.lock:
                return json.dumps(self.db)
        
        if c == "PRINTLOG":
            with self.lock:
                out = []
                for s in sorted(self.log.keys()):
                    ent = self.log[s]
                    out.append({
                        "seq": s,
                        "digest": ent.get("digest"),
                        "prepared": ent.get("prepared", False),
                        "committed": ent.get("committed", False),
                        "executed": ent.get("executed", False),
                        "result": ent.get("result")
                    })
                return json.dumps(out)
        
        if c == "PRINTCHECKPOINTS":
            with self.lock:
                ckpts = []
                for seq in sorted(self.checkpoints.keys()):
                    ckpt = self.checkpoints[seq]
                    ckpts.append({
                        "seq": seq,
                        "digest": ckpt.get("digest", "")[:16] + "...",
                        "stable": ckpt.get("stable", False),
                        "certificates": len(ckpt.get("certificates", []))
                    })
                return json.dumps({
                    "checkpoints": ckpts,
                    "stable_checkpoint": self.stable_checkpoint
                })
        
        if c == "PRINTVIEW":
            with self.lock:
                return json.dumps(self.new_view_messages)
        
        if c == "PRINTKEYS":
            with self.lock:
                return json.dumps({
                    "node_index": self.node_index,
                    "registered_keys": list(self.public_keys.keys()),
                    "my_key": self.my_pub_bytes()[:32] + "..."
                })
        
        if c == "UNSET_LEADER":
            with self.lock:
                self.is_primary = False
            return "OK"
        
        if c == "SET_PRIMARY":
            with self.lock:
                self.is_primary = True
                self.view = 0
                self.in_view_change = False
                self.last_progress_time = time.time()
                log(f"[R{self.node_index}] Manually set as PRIMARY")
            return "OK"
        
        if c.startswith("SET_VIEW"):
            parts = c.split()
            if len(parts) >= 2:
                try:
                    new_view = int(parts[1])
                    is_primary = len(parts) >= 3 and parts[2].upper() == "PRIMARY"
                    
                    with self.lock:
                        old_view = self.view
                        self.view = new_view
                        self.is_primary = is_primary
                        self.in_view_change = False
                        self.last_progress_time = time.time()
                        self.pending_requests.clear()
                        self.view_change_votes.clear()
                        
                        role = "PRIMARY" if is_primary else "BACKUP"
                        log(f"[R{self.node_index}] Manually set to {role} for view {new_view} (was view {old_view})")
                    
                    return "OK"
                except ValueError:
                    return "ERROR-INVALID-VIEW"
            return "ERROR-MISSING-VIEW"
        
        if c == "PAUSE_TIMERS":
            with self.lock:
                self.pause_timers = True
            return "OK"
        
        if c == "RESUME_TIMERS":
            with self.lock:
                self.pause_timers = False
                self.last_progress_time = time.time()
            return "OK"
        
        if c == "RESET_DB":
            with self.lock:
                self.db = {chr(ord('A') + i): 10 for i in range(10)}
            return "OK"
        
        if c == "RESET_STATE":
            with self.lock:
                saved_keys = dict(self.public_keys)
                print("\n" + "="*80 + "\n")
                self.db = {chr(ord('A') + i): 10 for i in range(10)}
                self.log = {}
                self.seq_number = 0
                self.last_executed = 0
                self.commit_index = 0
                self.prepare_quorum.clear()
                self.commit_quorum.clear()
                self.prepared_certs.clear()
                self.committed_certs.clear()
                self.checkpoints.clear()
                self.stable_checkpoint = 0
                self.checkpoint_votes.clear()
                self.view_change_log.clear()
                self.view_change_votes.clear()
                self.in_view_change = False
                self.last_progress_time = time.time()
                self.pending_clients.clear()
                self.pending_requests.clear()
                self.malicious_modes = {
                    'invalid_signature': False,
                    'crash': False,
                    'timing': False,
                    'dark': False,
                    'equivocation': False
                }
                self.dark_nodes = set()
                self.equivocation_nodes = set()
                self.equivocation_seq_offset = 0
                self.public_keys = saved_keys

                # Reset SmallBank state
                self.smallbank.reset()
                self.smallbank.initialize_accounts(num_accounts=100, initial_balance=10000)
                
                if GLOBAL_PUBLIC_KEYS and len(self.public_keys) < len(GLOBAL_PUBLIC_KEYS):
                    self.public_keys = dict(GLOBAL_PUBLIC_KEYS)
                    log(f"[R{self.node_index}] Full state reset completed (restored {len(self.public_keys)} public keys from global)")
                else:
                    log(f"[R{self.node_index}] Full state reset completed (preserved {len(self.public_keys)} public keys)")
            return "OK"
        
        if c.startswith("ATTACK"):
            parts = c.split()
            if len(parts) >= 2:
                attack_type = parts[1].strip().lower()
                with self.lock:
                    log(f"[R{self.node_index}] Processing ATTACK command: '{attack_type}'")
                    
                    if attack_type == "sign" or attack_type == "invalid_signature":
                        self.malicious_modes['invalid_signature'] = True
                        log(f"[R{self.node_index}] [BYZANTINE] *** Invalid signature attack ENABLED ***")
                        return "ATTACK-INVALID_SIGNATURE-ENABLED"
                    
                    elif attack_type == "crash":
                        self.malicious_modes['crash'] = True
                        log(f"[R{self.node_index}] [BYZANTINE] *** Crash attack ENABLED ***")
                        return "ATTACK-CRASH-ENABLED"
                    
                    elif attack_type == "time" or attack_type == "timing":
                        self.malicious_modes['timing'] = True
                        log(f"[R{self.node_index}] [BYZANTINE] *** Timing attack ENABLED (delay={self.timing_delay_ms}ms) ***")
                        return "ATTACK-TIMING-ENABLED"
                    
                    elif attack_type == "dark":
                        # Parse dark nodes from command: ATTACK DARK 5,6 or ATTACK DARK [5,6]
                        if len(parts) >= 3:
                            dark_spec = ' '.join(parts[2:]).strip()
                            # Remove brackets if present
                            dark_spec = dark_spec.strip('[]')
                            # Parse comma-separated node indices
                            dark_indices = []
                            for idx_str in dark_spec.split(','):
                                idx_str = idx_str.strip()
                                if idx_str:
                                    try:
                                        dark_indices.append(int(idx_str))
                                    except ValueError:
                                        pass
                            
                            self.dark_nodes = set(dark_indices)
                            self.malicious_modes['dark'] = True
                            log(f"[R{self.node_index}] [BYZANTINE] *** Dark attack ENABLED - excluding nodes: {sorted(self.dark_nodes)} ***")
                            log(f"[R{self.node_index}] [BYZANTINE-DARK] These nodes will NOT receive ANY messages from R{self.node_index}")
                            log(f"[R{self.node_index}] [BYZANTINE-DARK] They should TIMEOUT and initiate VIEW-CHANGE")
                            return f"ATTACK-DARK-ENABLED-{sorted(self.dark_nodes)}"
                        else:
                            return "ATTACK-DARK-MISSING-TARGETS"
                    
                    elif attack_type == "equivocation" or attack_type == "equivocate":
                        # Parse equivocation nodes from command: ATTACK EQUIVOCATION 6 or ATTACK EQUIVOCATION 5,6
                        if len(parts) >= 3:
                            equiv_spec = ' '.join(parts[2:]).strip()
                            # Remove brackets if present
                            equiv_spec = equiv_spec.strip('[]')
                            # Parse comma-separated node indices
                            equiv_indices = []
                            for idx_str in equiv_spec.split(','):
                                idx_str = idx_str.strip()
                                if idx_str:
                                    try:
                                        equiv_indices.append(int(idx_str))
                                    except ValueError:
                                        pass
                            
                            self.equivocation_nodes = set(equiv_indices)
                            self.malicious_modes['equivocation'] = True
                            log(f"[R{self.node_index}] [BYZANTINE] *** Equivocation attack ENABLED ***")
                            log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] Will send ALTERNATE sequence numbers to nodes: {sorted(self.equivocation_nodes)}")
                            log(f"[R{self.node_index}] [BYZANTINE-EQUIVOCATION] Majority gets seq=N, equivocated nodes get seq=N+1")
                            return f"ATTACK-EQUIVOCATION-ENABLED-{sorted(self.equivocation_nodes)}"
                        else:
                            return "ATTACK-EQUIVOCATION-MISSING-TARGETS"
                    
                    else:
                        log(f"[R{self.node_index}] Unknown attack type: '{attack_type}'")
                        return f"ATTACK-UNKNOWN-{attack_type.upper()}"
            log(f"[R{self.node_index}] ATTACK command missing type")
            return "ATTACK-NO-TYPE"
        
        return "UNKNOWN"

    def _primary_hint(self):
        return (self.view % N)

    def _digest(self, data):
        raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(raw)
        return digest.finalize().hex()

def spawn_all_replicas_in_process():
    global GLOBAL_PUBLIC_KEYS
    
    replicas = []
    pubmap = {}
    
    for i, (pp, ap) in enumerate(zip(PROTO_PORTS, ADMIN_PORTS)):
        r = ReplicaNode(pp, ap)
        pubmap[r.node_index] = r.my_pub_bytes()
        replicas.append(r)
        log(f"Created replica {r.node_index}, public key: {r.my_pub_bytes()[:32]}...")
    
    GLOBAL_PUBLIC_KEYS = dict(pubmap)
    
    for r in replicas:
        r.register_public_keys(pubmap)
        log(f"Replica {r.node_index} registered {len(r.public_keys)} public keys: {list(r.public_keys.keys())}")
    
    for r in replicas:
        r.start()
    
    return replicas

def main():
    global GLOBAL_PUBLIC_KEYS
    
    if len(sys.argv) >= 2 and sys.argv[1] == "--spawn-all":
        log("Spawning all replicas in single process...")
        replicas = spawn_all_replicas_in_process()
        log(f"All {len(replicas)} replicas spawned. Global keys: {list(GLOBAL_PUBLIC_KEYS.keys())}")
        log("Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log("Shutting down.")
            return
    
    if len(sys.argv) >= 2 and sys.argv[1] == "--generate-keys":
        log("Generating keys for all replicas...")
        pubmap = {}
        for i in range(N):
            sk, pk = new_ed25519_keypair()
            pk_hex = pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
            sk_hex = sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex()
            pubmap[i] = {"public": pk_hex, "private": sk_hex}
        
        with open("pbft_keys.json", "w") as f:
            json.dump(pubmap, f, indent=2)
        log(f"Generated and saved keys for {N} replicas to pbft_keys.json")
        return

    if len(sys.argv) < 3:
        print("Usage: python pbft_server.py <proto_port> <admin_port>")
        print(" or     python pbft_server.py --spawn-all")
        print(" or     python pbft_server.py --generate-keys (then run replicas)")
        sys.exit(1)

    proto = int(sys.argv[1])
    admin = int(sys.argv[2])
    
    r = ReplicaNode(proto, admin)
    
    try:
        with open("pbft_keys.json", "r") as f:
            key_data = json.load(f)
        
        node_idx = r.node_index
        if str(node_idx) in key_data:
            private_hex = key_data[str(node_idx)]["private"]
            public_hex = key_data[str(node_idx)]["public"]
            
            r.sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
            r.pk = r.sk.public_key()
            
            all_pubs = {int(k): v["public"] for k, v in key_data.items()}
            r.register_public_keys(all_pubs)
            GLOBAL_PUBLIC_KEYS = all_pubs
            
            log(f"Loaded shared keys from pbft_keys.json: {len(r.public_keys)} keys")
        else:
            log(f"[WARNING] No pre-generated key found for node {node_idx}, using own key only")
            r.register_public_keys({r.node_index: r.my_pub_bytes()})
    except FileNotFoundError:
        log(f"[WARNING] pbft_keys.json not found. Running with own key only.")
        log(f"[WARNING] For multi-process mode, run: python pbft_server.py --generate-keys first")
        r.register_public_keys({r.node_index: r.my_pub_bytes()})
    except Exception as e:
        log(f"[ERROR] Failed to load keys: {e}")
        r.register_public_keys({r.node_index: r.my_pub_bytes()})
    
    r.start()
    log(f"Replica started with {len(r.public_keys)} public key(s)")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("Replica shutting down")
        r.stop()

if __name__ == "__main__":
    main()
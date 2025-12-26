#!/usr/bin/env python3
"""
pbft_clients_controller.py
FIXED: Proper connection handling to avoid duplicate transactions
FEATURE: Broadcasts requests to all replicas for crash detection
"""
import multiprocessing as mp
import socket, json, time, random, sys
import threading
from typing import List

HOST = "127.0.0.1"
CONTROL_PORT = 18000

PROTO_PORTS = [7000 + i for i in range(7)]
ADMIN_PORTS = [17000 + i for i in range(7)]
NUM_CLIENTS = 10
CLIENT_NAMES = [chr(ord('A') + i) for i in range(NUM_CLIENTS)]

TIMEOUT = 3.0
RETRIES = 3
REPLY_WAIT_TIMEOUT = 20.0

def send_and_wait_for_reply(port, payload, timeout=TIMEOUT):
    """Send request and wait for REPLY message - FIXED to avoid retries"""
    try:
        with socket.create_connection((HOST, port), timeout=timeout) as s:
            s.settimeout(REPLY_WAIT_TIMEOUT)
            s.sendall((json.dumps(payload) + "\n").encode())
            
            buf = b""
            got_queued = False
            start_time = time.time()
            
            while time.time() - start_time < REPLY_WAIT_TIMEOUT:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        if got_queued:
                            return {"result": "timeout-after-queued"}
                        return None
                    
                    buf += chunk
                    
                    while b"\n" in buf:
                        line, _, buf = buf.partition(b"\n")
                        try:
                            resp = json.loads(line.decode())
                            
                            if resp.get("result") == "redirect":
                                return resp
                            
                            elif resp.get("result") == "queued":
                                got_queued = True
                                # Don't return yet, wait for REPLY
                                continue
                            
                            elif resp.get("type") == "REPLY":
                                # Got the execution result
                                return resp
                            
                            else:
                                return resp
                        except json.JSONDecodeError:
                            continue
                
                except socket.timeout:
                    if got_queued:
                        return {"result": "timeout-after-queued"}
                    return None
            
            if got_queued:
                return {"result": "timeout-after-queued"}
            return None
            
    except Exception as e:
        return None

def broadcast_to_backups(live_ports, payload, primary_port):
    """Fire-and-forget broadcast to backup nodes so they track requests"""
    for port in live_ports:
        if port != primary_port:
            try:
                # Short timeout, we don't wait for response
                threading.Thread(
                    target=send_and_wait_for_reply,
                    args=(port, payload, 0.2),
                    daemon=True
                ).start()
            except:
                pass

def discover_leader(live_ports: List[int]):
    """Query STATUS on admin ports to find primary"""
    for idx in range(len(PROTO_PORTS)):
        if PROTO_PORTS[idx] not in live_ports:
            continue
        admin_port = ADMIN_PORTS[idx]
        try:
            with socket.create_connection((HOST, admin_port), timeout=1.0) as s:
                s.settimeout(1.0)
                try:
                    _ = s.recv(1024)
                except:
                    pass
                s.sendall(b"STATUS\n")
                resp = s.recv(4096).decode().strip()
                st = json.loads(resp)
                if st.get("primary") or st.get("leader"):
                    return PROTO_PORTS[idx]
        except:
            continue
    return None

def client_worker(cid, request_q: mp.Queue, done_q: mp.Queue):
    """Worker process for each client (A-J) - FIXED retry logic"""
    name = CLIENT_NAMES[cid]
    while True:
        task = request_q.get()
        if task is None:
            break
        
        set_num = task.get("set_num")
        txns = task.get("txns", [])
        live = task.get("live_ports", list(PROTO_PORTS))

        for txn in txns:
            if not isinstance(txn, (list, tuple)):
                continue
            
            # Determine transaction type
            is_read = False
            client_account = None
            
            if len(txn) == 2 and txn[0] == "READ":
                is_read = True
                client_account = txn[1]
                if client_account != name:
                    continue
            elif len(txn) == 3:
                sender = txn[0]
                if sender != name:
                    continue
            else:
                continue
            
            # Retry loop - FIXED to avoid creating duplicate transactions
            attempt = 0
            success = False
            final_resp = None
            
            while attempt < RETRIES and not success:
                # Find primary for transfers, any replica for reads
                if is_read:
                    port = random.choice(live)
                else:
                    leader = discover_leader(live)
                    port = leader if leader else random.choice(live)
                
                # Build request
                if is_read:
                    payload = {
                        "type": "READ_REQUEST",
                        "client_id": cid,
                        "account": client_account,
                        "timestamp": int(time.time()*1000)
                    }
                else:
                    payload = {
                        "type": "REQUEST",
                        "client_id": cid,
                        "request": txn,
                        "timestamp": int(time.time()*1000)
                    }
                
                # CRITICAL: Broadcast request to ALL replicas (including backups)
                # This allows backups to track requests and detect primary crashes
                if not is_read:
                    broadcast_to_backups(live, payload, port)
                
                # Send and wait for response from primary
                resp = send_and_wait_for_reply(port, payload, timeout=TIMEOUT)
                
                if resp:
                    # Handle different response types
                    if resp.get("result") == "redirect":
                        # Retry with potentially new view
                        # Re-broadcast to all backups so they know about this request
                        if not is_read:
                            broadcast_to_backups(live, payload, port)
                        time.sleep(0.1)
                        continue
                    
                    if resp.get("type") == "READ_REPLY":
                        success = True
                        final_resp = resp
                        balance = resp.get("balance", "unknown")
                        account = resp.get("account", "unknown")
                        print(f"[Client {name}] ✓ READ response received: Account {account} has balance {balance}")
                        break
                    
                    if resp.get("type") == "REPLY":
                        # Got execution result
                        success = True
                        final_resp = resp
                        break
                    
                    if resp.get("result") == "timeout-after-queued":
                        # Transaction was queued but we didn't get REPLY
                        # This is likely a success, but we didn't get confirmation
                        # Don't retry as it would create duplicate transaction
                        success = False
                        final_resp = {"result": "timeout-no-reply"}
                        break
                
                # Only increment attempt if we actually contacted primary
                # and got an error (not redirect)
                if resp and resp.get("result") != "redirect":
                    attempt += 1
                else:
                    attempt += 1
                
                if not success:
                    time.sleep(0.2)
            
            # Report result
            done_q.put({
                "client": cid,
                "set_num": set_num,
                "txn": txn,
                "resp": final_resp,
                "success": success and final_resp is not None
            })

            if is_read and final_resp and final_resp.get("type") == "READ_REPLY":
                balance = final_resp.get("balance", "unknown")
                account = final_resp.get("account", "unknown")
                print(f"[Client {name}] Account {account} balance: {balance}")
            
            # Delay between transactions to avoid overwhelming system
            time.sleep(0.2)
    
    return

def control_server(client_queues, done_q: mp.Queue):
    """Control server listens for RUN_SET commands from admin controller"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, CONTROL_PORT))
    sock.listen(2)
    log = lambda *a, **k: print("[clients_ctrl]", *a, **k)
    log("Listening on", CONTROL_PORT)
    
    try:
        while True:
            conn, _ = sock.accept()
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        line, _, rest = data.partition(b"\n")
                        data = rest
                        try:
                            msg = json.loads(line.decode())
                        except:
                            conn.sendall(b'{"error":"bad-json"}\n')
                            break
                        
                        if msg.get("type") == "RUN_SET":
                            set_num = msg.get("set_num")
                            txns = msg.get("txns", [])
                            live_nodes = msg.get("live_nodes", list(range(len(PROTO_PORTS))))
                            live_ports = [PROTO_PORTS[i] for i in live_nodes if 0 <= i < len(PROTO_PORTS)]
                            
                            log(f"Received RUN_SET for set {set_num} with {len(txns)} transactions")
                            
                            # Dispatch transactions sequentially
                            total = 0
                            successful = 0
                            
                            for txn in txns:
                                if not isinstance(txn, (list, tuple)):
                                    continue
                                
                                # Determine which client handles this
                                cid = None
                                if len(txn) == 2 and txn[0] == "READ":
                                    account = txn[1]
                                    cid = ord(account.upper()) - ord('A')
                                elif len(txn) == 3:
                                    sender = txn[0]
                                    cid = ord(sender.upper()) - ord('A')
                                else:
                                    log(f"Skipping invalid transaction: {txn}")
                                    continue
                                
                                if not (0 <= cid < NUM_CLIENTS):
                                    log(f"Invalid client ID {cid} for txn {txn}")
                                    continue
                                
                                # Send to client worker
                                client_queues[cid].put({
                                    "set_num": set_num,
                                    "txns": [txn],
                                    "live_ports": live_ports
                                })
                                
                                # Wait for completion with timeout
                                got = False
                                t0 = time.time()
                                while time.time() - t0 < 30:  # 30 second timeout per transaction
                                    try:
                                        r = done_q.get(timeout=1.0)
                                        if r.get("client") == cid and r.get("set_num") == set_num:
                                            got = True
                                            total += 1
                                            if r.get("success"):
                                                successful += 1
                                            break
                                    except:
                                        pass
                                
                                if not got:
                                    log(f"WARNING: Transaction timed out: {txn}")
                                    total += 1
                            
                            # Send completion response
                            response = {
                                "type": "DONE",
                                "set_num": set_num,
                                "completed": total,
                                "successful": successful
                            }
                            conn.sendall((json.dumps(response) + "\n").encode())
                            log(f"Set {set_num} complete: successful")
                            print("\n" + "="*80 + "\n")
                        else:
                            conn.sendall(b'{"error":"unknown-type"}\n')
                        break
    finally:
        sock.close()

if __name__ == "__main__":
    mp.set_start_method("spawn" if sys.platform.startswith("win") else "fork")
    
    # Create client worker processes
    client_queues = [mp.Queue() for _ in range(NUM_CLIENTS)]
    done_q = mp.Queue()
    workers = []
    
    for cid in range(NUM_CLIENTS):
        p = mp.Process(target=client_worker, args=(cid, client_queues[cid], done_q))
        p.start()
        workers.append(p)
    
    try:
        control_server(client_queues, done_q)
    except KeyboardInterrupt:
        pass
    finally:
        # Shutdown workers
        for q in client_queues:
            q.put(None)
        for p in workers:
            p.join()
    
    print("Clients controller exiting.")
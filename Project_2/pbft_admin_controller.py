#!/usr/bin/env python3
"""
pbft_admin_controller.py - FINAL VERSION with Equivocation Attack Support
Supports all 5 Byzantine attacks:
  1. sign/signature - Invalid signatures
  2. crash - Node refuses to participate
  3. time/timing - Deliberately delays messages
  4. dark(n1,n2) - Excludes specific nodes from communication
  5. equivocation(n1,n2) - Sends different sequence numbers to different nodes
"""
import csv
import json
import socket
import sys
import time
import os
from typing import List, Dict, Any, Tuple

HOST = "127.0.0.1"

PROTO_PORTS = [7000 + i for i in range(7)]
ADMIN_PORTS = [17000 + i for i in range(7)]
CLIENTS_CONTROL_HOST = "127.0.0.1"
CLIENTS_CONTROL_PORT = 18000

CONNECT_TIMEOUT = 2.0
RECV_TIMEOUT = 6.0

LOG_DIR = "."

# ---------------- CSV parsing ----------------
def parse_list_field(field: str) -> List[int]:
    """Parse list field like '[0,1,2]' or '[n1,n2]'"""
    if not field:
        return []
    s = field.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    s = s.replace("'", "").replace('"', "")
    toks = [t.strip() for t in s.split(",") if t.strip() != ""]
    out = []
    for t in toks:
        if not t:
            continue
        if t.lower().startswith("n"):
            try:
                idx = int(t[1:]) - 1
                out.append(idx)
                continue
            except:
                pass
        try:
            out.append(int(t))
        except:
            pass
    return out

def parse_attack_field(field: str) -> dict:
    '''
    Parse attack field supporting multiple attacks with targets
    Examples:
      - "time" -> {"types": ["time"], "dark_nodes": [], "equivocation_nodes": []}
      - "dark(n6)" -> {"types": ["dark"], "dark_nodes": [5], "equivocation_nodes": []}
      - "equivocation(n7)" -> {"types": ["equivocation"], "dark_nodes": [], "equivocation_nodes": [6]}
      - "time; dark(n6); equivocation(n7)" -> {"types": ["time", "dark", "equivocation"], ...}
      - "equivocation(n5, n6)" -> {"types": ["equivocation"], "equivocation_nodes": [4, 5]}
    '''
    if not field:
        return {"types": [], "dark_nodes": [], "equivocation_nodes": []}
    
    s = field.strip()
    # Remove outer brackets if present
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    
    attack_types = []
    dark_nodes = []
    equivocation_nodes = []
    
    # Split by semicolon for multiple attacks
    parts = s.split(';')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        # Check for dark attack with nodes
        if 'dark(' in part.lower():
            if 'dark' not in attack_types:
                attack_types.append('dark')
            
            # Extract nodes from dark(n1, n2, ...)
            try:
                start = part.lower().index('dark(') + 5
                end = part.index(')', start)
                dark_spec = part[start:end]
                
                # Parse comma-separated node specs
                for node_spec in dark_spec.split(','):
                    node_spec = node_spec.strip()
                    if not node_spec:
                        continue
                    
                    # Handle n1, n2, ... format (convert to 0-based)
                    if node_spec.lower().startswith('n'):
                        try:
                            idx = int(node_spec[1:]) - 1
                            dark_nodes.append(idx)
                        except ValueError:
                            pass
                    else:
                        # Handle direct index
                        try:
                            idx = int(node_spec)
                            dark_nodes.append(idx)
                        except ValueError:
                            pass
            except (ValueError, IndexError):
                pass
        
        # Check for equivocation attack with nodes
        if 'equivocation(' in part.lower() or 'equivocate(' in part.lower():
            if 'equivocation' not in attack_types:
                attack_types.append('equivocation')
            
            # Extract nodes from equivocation(n1, n2, ...)
            try:
                # Find the opening parenthesis
                if 'equivocation(' in part.lower():
                    start = part.lower().index('equivocation(') + 13
                else:
                    start = part.lower().index('equivocate(') + 11
                end = part.index(')', start)
                equiv_spec = part[start:end]
                
                # Parse comma-separated node specs
                for node_spec in equiv_spec.split(','):
                    node_spec = node_spec.strip()
                    if not node_spec:
                        continue
                    
                    # Handle n1, n2, ... format (convert to 0-based)
                    if node_spec.lower().startswith('n'):
                        try:
                            idx = int(node_spec[1:]) - 1
                            equivocation_nodes.append(idx)
                        except ValueError:
                            pass
                    else:
                        # Handle direct index
                        try:
                            idx = int(node_spec)
                            equivocation_nodes.append(idx)
                        except ValueError:
                            pass
            except (ValueError, IndexError):
                pass
        
        # Check for other attack types (independent of parameter parsing)
        if 'time' in part.lower() or 'timing' in part.lower():
            if 'time' not in attack_types and 'timing' not in attack_types:
                attack_types.append('time')
        
        if 'sign' in part.lower() or 'signature' in part.lower():
            if 'sign' not in attack_types:
                attack_types.append('sign')
        
        if 'crash' in part.lower() and 'dark' not in part.lower():
            # Don't match 'dark' as 'crash'
            if 'crash' not in attack_types:
                attack_types.append('crash')
    
    return {
        "types": attack_types,
        "dark_nodes": sorted(list(set(dark_nodes))),  # Remove duplicates
        "equivocation_nodes": sorted(list(set(equivocation_nodes)))
    }

def parse_transaction(txn_field: str, set_num: int) -> tuple:
    """Parse transaction field"""
    tf = txn_field.strip()
    
    if not tf:
        raise ValueError(f"Empty transaction field on set {set_num}")
    
    has_parens = tf.startswith("(") and tf.endswith(")")
    if has_parens:
        tf = tf[1:-1].strip()
    
    parts = [p.strip() for p in tf.split(",")]
    parts = [p for p in parts if p]
    
    if len(parts) == 1:
        return ("READ", parts[0])
    elif len(parts) == 3:
        try:
            amount = int(parts[2])
        except ValueError:
            raise ValueError(f"Bad amount in transaction on set {set_num}: '{txn_field}'")
        return (parts[0], parts[1], amount)
    else:
        raise ValueError(f"Bad txn field on set {set_num}: '{txn_field}'")

def load_sets_from_csv(path: str) -> List[Dict[str, Any]]:
    """Load test sets from CSV"""
    rows_by_set = {}
    last_set = None

    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        all_rows = list(reader)

    start = 0
    while start < len(all_rows):
        row = all_rows[start]
        if not row or all((not c or c.strip() == "") for c in row):
            start += 1
            continue
        first_cell = (row[0] or "").strip().lstrip("\ufeff")
        try:
            _ = int(first_cell)
            break
        except:
            start += 1
            continue

    for raw in all_rows[start:]:
        if not raw or all((not c or c.strip() == "") for c in raw):
            continue
        
        while len(raw) < 5:
            raw.append("")
        
        set_cell = (raw[0] or "").strip().lstrip("\ufeff")
        txn_field = (raw[1] or "").strip()
        live_field = (raw[2] or "").strip()
        byz_field = (raw[3] or "").strip()
        attack_field = (raw[4] or "").strip()

        if set_cell == "":
            if last_set is None:
                raise ValueError("CSV format error: first data row missing set number")
            set_num = last_set
        else:
            try:
                set_num = int(set_cell)
            except:
                raise ValueError(f"CSV format error: expected int but got '{set_cell}'")
            last_set = set_num

        txn_parsed = parse_transaction(txn_field, set_num)
        live_nodes = parse_list_field(live_field) if live_field else None
        byz_nodes = parse_list_field(byz_field) if byz_field else []
        attack_info = parse_attack_field(attack_field)

        rows_by_set.setdefault(set_num, []).append((txn_parsed, live_nodes, byz_nodes, attack_info))

    # Combine rows into sets
    sets = []
    for s in sorted(rows_by_set.keys()):
        items = rows_by_set[s]
        txns = [t for (t, ln, bn, ai) in items]
        
        chosen_live = None
        chosen_byz = set()
        all_attack_types = set()
        all_dark_nodes = set()
        all_equivocation_nodes = set()
        
        for (t, ln, bn, ai) in items:
            if chosen_live is None and ln is not None:
                chosen_live = ln
            if bn:
                for b in bn:
                    chosen_byz.add(b)
            if ai:
                for at in ai.get('types', []):
                    all_attack_types.add(at)
                for dn in ai.get('dark_nodes', []):
                    all_dark_nodes.add(dn)
                for en in ai.get('equivocation_nodes', []):
                    all_equivocation_nodes.add(en)
        
        if chosen_live is None:
            chosen_live = list(range(len(PROTO_PORTS)))
        
        sets.append({
            "set_num": s,
            "txns": txns,
            "live_nodes": chosen_live,
            "byzantine_nodes": sorted(list(chosen_byz)),
            "attack_types": sorted(list(all_attack_types)),
            "dark_nodes": sorted(list(all_dark_nodes)),
            "equivocation_nodes": sorted(list(all_equivocation_nodes))
        })
    
    return sets

# ---------------- networking helpers ----------------
def send_admin_cmd(admin_port: int, cmd: str, timeout=CONNECT_TIMEOUT) -> Tuple[bool, str]:
    """Send admin command and return (ok, response)"""
    try:
        with socket.create_connection((HOST, admin_port), timeout=timeout) as s:
            s.settimeout(RECV_TIMEOUT)
            try:
                _ = s.recv(1024)
            except:
                pass
            s.sendall((cmd + "\n").encode())
            try:
                resp = s.recv(8192).decode()
                return True, resp.strip()
            except:
                return True, "<no-response>"
    except Exception as e:
        return False, str(e)

def check_all_nodes_status(live_nodes: List[int]) -> Dict[int, Any]:
    """Query STATUS from all live nodes"""
    statuses = {}
    for idx in live_nodes:
        admin_port = ADMIN_PORTS[idx]
        ok, resp = send_admin_cmd(admin_port, "STATUS", timeout=1.5)
        if ok and resp and resp != "<no-response>":
            try:
                statuses[idx] = json.loads(resp)
            except:
                statuses[idx] = {"raw": resp}
        else:
            statuses[idx] = {"error": f"connection failed: {resp}"}
    return statuses

def set_servers_live_fail(live_nodes: List[int]):
    """Set nodes to RECOVER or FAIL"""
    results = []
    desired = set(live_nodes)
    for i in range(len(ADMIN_PORTS)):
        p = ADMIN_PORTS[i]
        if i in desired:
            ok, resp = send_admin_cmd(p, "RECOVER")
        else:
            ok, resp = send_admin_cmd(p, "FAIL")
        results.append((i, ok, resp))
    return results

def unset_leader_all():
    """Clear leader flags on all nodes"""
    res = []
    for p in ADMIN_PORTS:
        ok, resp = send_admin_cmd(p, "UNSET_LEADER")
        res.append((p, ok, resp))
    return res

def pause_timers_all():
    """Pause timers on all nodes"""
    res = []
    for p in ADMIN_PORTS:
        ok, resp = send_admin_cmd(p, "PAUSE_TIMERS")
        res.append((p, ok, resp))
    return res

def resume_timers_all():
    """Resume timers on all nodes"""
    res = []
    for p in ADMIN_PORTS:
        ok, resp = send_admin_cmd(p, "RESUME_TIMERS")
        res.append((p, ok, resp))
    return res

def reset_all_nodes():
    """Reset database and state on all nodes"""
    res = []
    for p in ADMIN_PORTS:
        ok, resp = send_admin_cmd(p, "RESET_STATE")
        res.append((p, ok, resp))
    return res

def send_run_set_to_clients(set_obj: Dict[str, Any]) -> Tuple[bool, Any]:
    """Send RUN_SET to clients controller"""
    attack_types = set_obj.get("attack_types", [])
    base_timeout = 300
    
    # Timing attack needs much longer timeout
    if 'time' in attack_types or 'timing' in attack_types:
        timeout = base_timeout * 3  # 15 minutes for timing attack
        print(f"[ADMIN] Using extended timeout ({timeout}s) for timing attack")
    else:
        timeout = base_timeout
    
    payload = {
        "type": "RUN_SET",
        "set_num": set_obj["set_num"],
        "txns": set_obj["txns"],
        "live_nodes": set_obj["live_nodes"],
        "timeout": timeout
    }
    try:
        with socket.create_connection((CLIENTS_CONTROL_HOST, CLIENTS_CONTROL_PORT), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(timeout + 10)
            s.sendall((json.dumps(payload) + "\n").encode())
            data = b""
            t0 = time.time()
            while time.time() - t0 < timeout + 10:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        line, _, _ = data.partition(b"\n")
                        try:
                            return True, json.loads(line.decode())
                        except:
                            return False, {"error": "bad-json-reply", "raw": line.decode(errors="ignore")}
                except:
                    pass
            return False, {"error": "timeout waiting for clients"}
    except Exception as e:
        return False, {"error": str(e)}

def collect_and_log_outputs(set_obj: Dict[str, Any], live_nodes: List[int], logfile_path: str) -> None:
    """Collect PRINTDB, PRINTLOG, PRINTVIEW from replicas"""
    with open(logfile_path, "a", encoding="utf-8") as f:
        f.write("\n=== RESULTS for set {} ===\n".format(set_obj["set_num"]))
        f.write("Live nodes: {}\n".format(live_nodes))
        f.write("Byzantine nodes: {}\n".format(set_obj.get("byzantine_nodes", [])))
        f.write("Attack types: {}\n".format(set_obj.get("attack_types")))
        f.write("Dark nodes: {}\n".format(set_obj.get("dark_nodes")))
        f.write("Equivocation nodes: {}\n".format(set_obj.get("equivocation_nodes")))

        # PRINTDB
        f.write("\n-- FINAL DATABASE STATE from live nodes --\n")
        dbs = {}
        for idx in live_nodes:
            ok, resp = send_admin_cmd(ADMIN_PORTS[idx], "PRINTDB", timeout=2.0)
            if ok and resp:
                try:
                    parsed = json.loads(resp)
                    dbs[idx] = parsed
                    f.write(f" node[{idx}] DB: {json.dumps(parsed, sort_keys=True)}\n")
                except:
                    f.write(f" node[{idx}] DB: <non-json: {resp}>\n")
            else:
                f.write(f" node[{idx}] DB: <no-response: {resp}>\n")

        # Print final database state to console
        if dbs:
            print(f"\n[ADMIN] Final Database State for Set {set_obj['set_num']}:")
            node_items = list(dbs.items())
            canon_idx, canon_db = node_items[0]
            print(f"  Primary/Reference (node[{canon_idx}]): {json.dumps(canon_db, sort_keys=True)}")
            
            # Compare DBs
            mismatch = any(db != canon_db for (_, db) in node_items[1:])
            if mismatch:
                f.write("\n[WARNING] MISMATCH detected between replicas' DBs!\n")
                print(f"  [WARNING] MISMATCH DETECTED!")
                for idx, db in node_items:
                    if db != canon_db:
                        f.write(f"  node[{idx}] differs from node[{canon_idx}]\n")
                        print(f"  node[{idx}]: {json.dumps(db, sort_keys=True)} (DIFFERS)")
            else:
                f.write("\n[OK] All live replicas agree on DB state.\n")
                print(f"  [OK] All {len(node_items)} live replicas agree on final state")

        # PRINTLOG
        f.write("\n-- PRINTLOG previews --\n")
        for idx in live_nodes:
            ok, resp = send_admin_cmd(ADMIN_PORTS[idx], "PRINTLOG", timeout=2.0)
            if ok and resp:
                f.write(f" node[{idx}] LOG: {str(resp)[:800]}\n")
            else:
                f.write(f" node[{idx}] LOG: <no-response: {resp}>\n")

        # PRINTVIEW
        f.write("\n-- PRINTVIEW previews --\n")
        for idx in live_nodes:
            ok, resp = send_admin_cmd(ADMIN_PORTS[idx], "PRINTVIEW", timeout=2.0)
            if ok and resp:
                f.write(f" node[{idx}] VIEW: {str(resp)[:400]}\n")
            else:
                f.write(f" node[{idx}] VIEW: <no-response: {resp}>\n")

        # PRINTCHECKPOINTS
        f.write("\n-- CHECKPOINTS from live nodes --\n")
        for idx in live_nodes:
            ok, resp = send_admin_cmd(ADMIN_PORTS[idx], "PRINTCHECKPOINTS", timeout=2.0)
            if ok and resp:
                try:
                    ckpt_data = json.loads(resp)
                    f.write(f" node[{idx}] CHECKPOINTS:\n")
                    f.write(f"   Stable checkpoint: {ckpt_data.get('stable_checkpoint')}\n")
                    for ckpt in ckpt_data.get('checkpoints', []):
                        stable_mark = " [STABLE]" if ckpt.get('stable') else ""
                        f.write(f"   seq={ckpt['seq']}, digest={ckpt['digest']}, "
                               f"certs={ckpt['certificates']}{stable_mark}\n")
                except:
                    f.write(f" node[{idx}] CHECKPOINTS: {str(resp)[:400]}\n")
            else:
                f.write(f" node[{idx}] CHECKPOINTS: <no-response: {resp}>\n")

        f.write("\n=== End results for set {} ===\n".format(set_obj["set_num"]))

# ---------------- orchestration ----------------
def run_sets(sets: List[Dict[str, Any]]):
    """Run all test sets"""
    for s in sets:
        setnum = s["set_num"]
        txns = s["txns"]
        live_nodes = s["live_nodes"]
        byz_nodes = s.get("byzantine_nodes", [])
        attack_types = s.get("attack_types", [])
        dark_nodes = s.get("dark_nodes", [])
        equiv_nodes = s.get("equivocation_nodes", [])

        logfile = os.path.join(LOG_DIR, f"admin_log_Set{setnum}.txt")
        print("\n" + "=" * 70)
        print(f"Running Set {setnum}")
        print(f"  Live nodes: {live_nodes} (R{',R'.join(map(str, live_nodes))})")
        if byz_nodes:
            print(f"  Byzantine nodes: {byz_nodes} (R{',R'.join(map(str, byz_nodes))})")
        else:
            print(f"  Byzantine nodes: none")
        print(f"  Attack types: {attack_types}")
        if dark_nodes:
            print(f"  Dark nodes (excluded): {dark_nodes} (R{',R'.join(map(str, dark_nodes))})")
        if equiv_nodes:
            print(f"  Equivocation nodes (alternate seq): {equiv_nodes} (R{',R'.join(map(str, equiv_nodes))})")
        print(f"  Transactions: {len(txns)}")
        
        # Warning for timing attack
        if 'time' in attack_types or 'timing' in attack_types:
            print(f"  [WARNING] Timing attack detected - expect SLOW execution (~8-10s per txn)")
        
        # Warning for dark attack
        if 'dark' in attack_types and dark_nodes:
            print(f"  [WARNING] Dark attack detected - nodes {dark_nodes} will be ISOLATED")
            print(f"            They should TIMEOUT and initiate VIEW-CHANGE")
        
        # Warning for equivocation attack
        if 'equivocation' in attack_types and equiv_nodes:
            print(f"  [WARNING] Equivocation attack detected - nodes {equiv_nodes} get DIFFERENT seq numbers")
            print(f"            Majority gets seq=N, equivocated nodes get seq=N+1")
            print(f"            Only majority should reach quorum and execute")
        
        print("=" * 70)
        
        with open(logfile, "w", encoding="utf-8") as f:
            f.write(f"Admin log for Set {setnum}\n")
            f.write(f"Live nodes: {live_nodes}\n")
            f.write(f"Byzantine nodes: {byz_nodes}\n")
            f.write(f"Attack types: {attack_types}\n")
            f.write(f"Dark nodes: {dark_nodes}\n")
            f.write(f"Equivocation nodes: {equiv_nodes}\n")
            f.write(f"Transactions ({len(txns)}): {txns}\n\n")

        # 1) Reset all nodes first (except for Set 1)
        if setnum > 1:
            print(f"[ADMIN] Resetting all nodes from previous set...")
            reset_res = reset_all_nodes()
            time.sleep(1.0)

        # 2) Resume timers
        print("[ADMIN] Resuming timers on all nodes...")
        resume_timers_all()
        time.sleep(0.5)

        # 3) Set RECOVER/FAIL
        print("[ADMIN] Configuring node states (RECOVER/FAIL)...")
        res = set_servers_live_fail(live_nodes)
        for (idx, ok, resp) in res:
            with open(logfile, "a", encoding="utf-8") as f:
                cmd = 'RECOVER' if idx in live_nodes else 'FAIL'
                f.write(f"  server[{idx}] -> {cmd}; ok={ok}; resp={str(resp)[:200]}\n")

        time.sleep(1.0)

        # 4) Clear leader flags
        print("[ADMIN] Clearing leader flags (UNSET_LEADER)...")
        ul = unset_leader_all()
        time.sleep(0.5)

        # 5) Configure Byzantine nodes
        if byz_nodes:
            print(f"[ADMIN] Configuring Byzantine nodes: {byz_nodes}")
            print(f"[ADMIN] Attack types: {attack_types}")
            
            for b in byz_nodes:
                if 0 <= b < len(ADMIN_PORTS):
                    print(f"  [ADMIN] Configuring node[{b}] (R{b}) as Byzantine...")
                    
                    ok, resp = send_admin_cmd(ADMIN_PORTS[b], "RECOVER")
                    with open(logfile, "a", encoding="utf-8") as f:
                        f.write(f"  byz server[{b}] RECOVER; ok={ok}; resp={str(resp)[:200]}\n")
                    
                    # Apply each attack type
                    for attack in attack_types:
                        attack_cmd = attack.strip().upper()
                        if attack_cmd == 'TIME':
                            attack_cmd = 'TIMING'
                        
                        # Special handling for dark attack
                        if attack_cmd == 'DARK':
                            if dark_nodes:
                                dark_list = ','.join(map(str, dark_nodes))
                                attack_cmd = f"DARK {dark_list}"
                                print(f"  [ADMIN] Sending 'ATTACK {attack_cmd}' to node[{b}]...")
                            else:
                                print(f"  [WARNING] Dark attack specified but no dark nodes provided")
                                continue
                        
                        # Special handling for equivocation attack
                        elif attack_cmd == 'EQUIVOCATION':
                            if equiv_nodes:
                                equiv_list = ','.join(map(str, equiv_nodes))
                                attack_cmd = f"EQUIVOCATION {equiv_list}"
                                print(f"  [ADMIN] Sending 'ATTACK {attack_cmd}' to node[{b}]...")
                            else:
                                print(f"  [WARNING] Equivocation attack specified but no equivocation nodes provided")
                                continue
                        else:
                            print(f"  [ADMIN] Sending 'ATTACK {attack_cmd}' to node[{b}]...")
                        
                        ok2, resp2 = send_admin_cmd(ADMIN_PORTS[b], f"ATTACK {attack_cmd}")
                        with open(logfile, "a", encoding="utf-8") as f:
                            f.write(f"  byz server[{b}] ATTACK {attack_cmd}; ok={ok2}; resp={str(resp2)[:200]}\n")
                        
                        print(f"  [ADMIN] Response from node[{b}]: '{resp2}'")
                        
                        if ok2 and ("ENABLED" in resp2.upper() or "OK" in resp2.upper()):
                            print(f"  [OK] Node[{b}] (R{b}) attack '{attack}' ENABLED")
                        else:
                            print(f"  [WARNING] Node[{b}] attack command returned: {resp2}")
                    
                    time.sleep(0.2)

        # 6) Manually elect primary
        print("[ADMIN] Manually electing primary with view consensus...")
        
        # DETERMINE WHICH NODES TO SKIP BASED ON ATTACK TYPE
        if 'crash' in attack_types:
            # Crash attack: Skip Byzantine nodes as primary
            non_byzantine_live = [n for n in live_nodes if n not in byz_nodes]
            print(f"[ADMIN] Crash attack detected - skipping Byzantine nodes: {byz_nodes}")
        else:
            # Timing, signature, dark, or equivocation attack: Byzantine nodes can be primary
            non_byzantine_live = live_nodes
            if 'time' in attack_types or 'timing' in attack_types:
                print(f"[ADMIN] Timing attack - Byzantine node CAN be primary (will be slow)")
            if 'dark' in attack_types:
                print(f"[ADMIN] Dark attack - Byzantine node CAN be primary (will exclude {dark_nodes})")
            if 'sign' in attack_types:
                print(f"[ADMIN] Signature attack - Byzantine node CAN be primary (signatures invalid)")
            if 'equivocation' in attack_types:
                print(f"[ADMIN] Equivocation attack - Byzantine node CAN be primary (will equivocate to {equiv_nodes})")

        if not non_byzantine_live:
            print("[ADMIN] [ERROR] No eligible nodes available to be primary!")
            with open(logfile, "a", encoding="utf-8") as f:
                f.write(f"\n[ERROR] No eligible nodes for primary election\n")
            primary_idx = None
        else:
            # Calculate view that gives us an eligible primary
            target_view = 0
            max_attempts = len(PROTO_PORTS)
            
            for attempt in range(max_attempts):
                candidate_primary = target_view % len(PROTO_PORTS)
                
                # Check if candidate is in eligible list
                if candidate_primary in non_byzantine_live:
                    primary_idx = candidate_primary
                    break
                
                target_view += 1
            else:
                # Fallback
                primary_idx = non_byzantine_live[0]
                target_view = primary_idx
            
            print(f"[ADMIN] Setting view={target_view}, primary=node[{primary_idx}]")
            
            if attack_types:
                if 'time' in attack_types or 'timing' in attack_types:
                    if primary_idx in byz_nodes:
                        print(f"[ADMIN] [INFO] Byzantine node {primary_idx} elected as primary (timing attack)")
                        print(f"[ADMIN] [INFO] Protocol will be SLOW but should complete correctly")
                
                if 'dark' in attack_types and dark_nodes:
                    print(f"[ADMIN] [INFO] Primary will ISOLATE nodes: {dark_nodes}")
                    print(f"[ADMIN] [INFO] Isolated nodes should timeout and attempt VIEW-CHANGE")
                
                if 'equivocation' in attack_types and equiv_nodes:
                    print(f"[ADMIN] [INFO] Primary will send DIFFERENT seq numbers to: {equiv_nodes}")
                    print(f"[ADMIN] [INFO] Majority gets seq=N, equivocated nodes get seq=N+1")
                    print(f"[ADMIN] [INFO] Only majority should reach quorum (2f+1=5)")
            
            # Set view on ALL live nodes
            success_count = 0
            for node_idx in live_nodes:
                if node_idx == primary_idx:
                    cmd = f"SET_VIEW {target_view} PRIMARY"
                    ok, resp = send_admin_cmd(ADMIN_PORTS[node_idx], cmd, timeout=2.0)
                    
                    if ok and resp == "OK":
                        print(f"  [OK] node[{node_idx}] set as PRIMARY for view {target_view}")
                        success_count += 1
                    else:
                        print(f"  [ERROR] node[{node_idx}] SET_VIEW PRIMARY failed: {resp}")
                else:
                    cmd = f"SET_VIEW {target_view} BACKUP"
                    ok, resp = send_admin_cmd(ADMIN_PORTS[node_idx], cmd, timeout=2.0)
                    
                    if ok and resp == "OK":
                        print(f"  [OK] node[{node_idx}] set as BACKUP for view {target_view}")
                        success_count += 1
                    else:
                        print(f"  [ERROR] node[{node_idx}] SET_VIEW BACKUP failed: {resp}")
            
            if success_count == len(live_nodes):
                print(f"[ADMIN] [OK] All {len(live_nodes)} nodes configured for view {target_view}")
                with open(logfile, "a", encoding="utf-8") as f:
                    f.write(f"\nView {target_view} established successfully\n")
                    f.write(f"  Primary: node[{primary_idx}]\n")
                    f.write(f"  Backups: {[n for n in live_nodes if n != primary_idx]}\n")
                    if byz_nodes:
                        f.write(f"  Byzantine nodes: {byz_nodes}\n")
                    if dark_nodes:
                        f.write(f"  Dark nodes (isolated): {dark_nodes}\n")
                    if equiv_nodes:
                        f.write(f"  Equivocation nodes (alternate seq): {equiv_nodes}\n")
            else:
                print(f"[ADMIN] [WARNING] Only {success_count}/{len(live_nodes)} nodes configured successfully")

        time.sleep(1.5)

        # 7) Verify primary election
        print("[ADMIN] Verifying primary status...")
        statuses = check_all_nodes_status(live_nodes)
        primaries = [idx for idx, st in statuses.items() if isinstance(st, dict) and st.get("primary")]
        
        if len(primaries) == 1:
            print(f"[ADMIN] [OK] Primary confirmed: node[{primaries[0]}]")
        elif len(primaries) == 0:
            print(f"[ADMIN] [WARNING] No primary detected after manual election!")
        else:
            print(f"[ADMIN] [WARNING] Multiple primaries detected: {primaries}")

        # 8) Send transactions to clients
        print(f"[ADMIN] Sending {len(txns)} transactions to clients controller...")
        
        if 'time' in attack_types or 'timing' in attack_types:
            estimated_time = len(txns) * 10
            print(f"[ADMIN] [WARNING] Timing attack active - estimated completion time: ~{estimated_time} seconds")
        
        if 'equivocation' in attack_types and equiv_nodes:
            print(f"[ADMIN] [INFO] Equivocation attack: expect some nodes to fall behind")
            print(f"[ADMIN] [INFO] Nodes {equiv_nodes} will receive alternate seq numbers")
            print(f"[ADMIN] [INFO] They won't reach quorum and won't execute")
        
        ok, resp = send_run_set_to_clients(s)
        if ok:
            completed = resp.get("completed", 0)
            successful = resp.get("successful", 0)
            print(f"[ADMIN] [OK] Clients completed")
            with open(logfile, "a", encoding="utf-8") as f:
                f.write(f"\nClients controller response: {json.dumps(resp)}\n")
        else:
            print(f"[ADMIN] [ERROR] Clients controller error: {resp}")
            with open(logfile, "a", encoding="utf-8") as f:
                f.write(f"\nClients controller ERROR: {json.dumps(resp)}\n")

        # 9) Allow settle time
        settle_time = 10.0 if ('time' in attack_types or 'timing' in attack_types) else 5.0
        print(f"[ADMIN] Allowing {settle_time}s settle time...")
        time.sleep(settle_time)

        # 10) Collect and log outputs
        print("[ADMIN] Collecting results from replicas...")
        collect_and_log_outputs(s, live_nodes, logfile)

        # 11) Pause timers
        print("[ADMIN] Pausing timers on all replicas...")
        pause_timers_all()
        time.sleep(0.2)

        print(f"[ADMIN] [OK] Set {setnum} complete. Log: {logfile}")
        print("=" * 70)

    print("\n[ADMIN] All test sets completed!")

def main():
    if len(sys.argv) < 2:
        print("Usage: python pbft_admin_controller.py <CSV_FILE>")
        print("Example: python pbft_admin_controller.py CSE535-F25-Project-2-Testcases.csv")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"ERROR: CSV file not found: '{csv_path}'")
        sys.exit(1)

    print("[ADMIN] Loading test cases from CSV...")
    sets = load_sets_from_csv(csv_path)
    print(f"[ADMIN] Loaded {len(sets)} test set(s)")
    
    for s in sets:
        print(f"\n[DEBUG] Set {s['set_num']} parsed:")
        print(f"  Live nodes: {s['live_nodes']}")
        print(f"  Byzantine nodes: {s['byzantine_nodes']}")
        print(f"  Attack types: {s['attack_types']}")
        print(f"  Dark nodes: {s['dark_nodes']}")
        print(f"  Equivocation nodes: {s['equivocation_nodes']}")
        print(f"  Transactions: {len(s['txns'])}")
    
    run_sets(sets)

if __name__ == "__main__":
    main()
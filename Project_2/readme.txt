PBFT Implementation with Byzantine Attack Support and SmallBank Benchmark
Overview
Complete Practical Byzantine Fault Tolerance (PBFT) consensus system with support for 5 Byzantine attack types and SmallBank benchmark integration. Supports N=7 replicas with f=2 Byzantine fault tolerance.
Core PBFT Features
Three-Phase Consensus Protocol:

PRE-PREPARE: Primary broadcasts sequence number and request digest
PREPARE: Backups validate and send prepare messages to primary
COMMIT: Primary collects quorum (2f+1=5) and broadcasts commit certificate
Execution happens after commit quorum is reached

View Change & Leader Election:

Automatic primary crash detection via timeout mechanism
Backups track pending requests and detect silent primary failures
Quorum-based view change protocol elects new primary
NEW-VIEW message synchronizes replicas in new view

Checkpointing & State Transfer:

Periodic checkpoints every K transactions (K=3)
Stable checkpoints with 2f+1 certificates
State transfer for replicas lagging behind stable checkpoint

Byzantine Attack Support
1. Invalid Signature Attack (sign/signature):

Byzantine node sends messages with corrupted signatures
Corrupted signatures rejected during validation
Byzantine node excluded from all quorum counts

2. Crash Attack:

Byzantine primary refuses to send PRE-PREPARE messages
Byzantine backups refuse to send PREPARE/COMMIT messages
Triggers timeout-based view change to elect new primary

3. Timing Attack (time/timing):

Byzantine node deliberately delays messages by ~500ms
Slows protocol execution but maintains correctness
Protocol completes successfully despite delays

4. Dark Attack (dark(n1,n2)):

Byzantine primary excludes specific nodes from communication
Isolated nodes timeout and initiate view change
Tests protocol resilience to network partitioning

5. Equivocation Attack (equivocation(n1,n2)):

Byzantine primary sends different sequence numbers to different nodes
Majority receives seq=N, minority receives seq=10000+N (isolated range)
Only majority reaches quorum and executes transactions
Minority nodes cannot execute due to missing quorum

SmallBank Benchmark Integration
Database Structure:

Three tables: customers, savings, checking
100-10,000 accounts with configurable initial balance
Zipf distribution (α=0.9) for skewed access patterns

Six Transaction Types:

BALANCE (15%): Read checking + savings balance
DEPOSIT_CHECKING (15%): Deposit to checking account
TRANSACT_SAVINGS (15%): Add/subtract from savings
AMALGAMATE (15%): Transfer all savings to checking
WRITE_CHECK (25%): Deduct from checking account
SEND_PAYMENT (15%): Transfer between two accounts

Performance Metrics:

Throughput (transactions/second)
Latency statistics (mean, median, P95, P99)
Transaction type distribution
Success/failure rates
Automated plot generation

Architecture
Components:

pbft_server.py: Replica node with PBFT protocol + Byzantine attacks + SmallBank handler
pbft_clients_controller.py: Client manager with broadcast-to-all for crash detection
pbft_admin_controller.py: Test orchestration with CSV-based test case loading
smallbank_benchmark.py: SmallBank workload generator and performance analyzer

Network Configuration:

Protocol ports: 7000-7006 (replica communication)
Admin ports: 17000-17006 (test control)
Client control port: 18000

Key Implementation Details
Quorum Counting:

2f+1 = 5 replicas required for prepare/commit certificates
Primary collects votes and broadcasts COLLECT messages
Byzantine nodes with invalid signatures not counted toward quorum

Request Tracking:

Clients broadcast requests to ALL replicas (not just primary)
Backups track requests and detect primary crashes via timeout
Primary timeout triggers automatic view change

Sequence Number Management:

Primary assigns monotonic sequence numbers
Equivocation attack uses isolated range (10000+) for minority
Majority continues with consecutive sequences ensuring smooth execution

State Consistency:

All replicas execute committed transactions in sequence order
Database state synchronized via checkpoints
State transfer catches up lagging replicas

Testing Framework
CSV-based test cases specify:

Transaction sequences
Live node configuration
Byzantine node assignments
Attack types (signature, crash, timing, dark, equivocation)
Attack targets (dark nodes, equivocation nodes)

Admin controller orchestrates:

Node initialization and key distribution
View setup and primary election
Byzantine attack configuration
Transaction execution and result verification
Final state comparison across replicas
RetryClaude can make mistakes. Please double-check responses.
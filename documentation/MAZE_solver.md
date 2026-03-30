# MAZE Solver: Secure Wumpus-World Navigation over Encrypted A2A Sessions

## Overview

This document describes the maze-solving application built on top of the encrypted Agent-to-Agent (A2A) protocol.

The application uses:
- Encrypted peer sessions between Traveller and Helper
- Session-based messaging with sequence protection
- A Wumpus-world-like maze memory on Helper
- Live map visualization on Traveller (matplotlib)
- Manual and automated (DFS) navigation modes

The key idea is simple:
- Traveller sends coordinates to Helper
- Helper evaluates maze rules and sends adjacency intelligence
- Traveller updates a live knowledge map and chooses next move

## Application Roles

### Traveller Agent (Explorer)

Responsibilities:
- Starts maze mode from CLI
- Sends coordinate probes to Helper
- Receives adjacency results
- Maintains visual map of discovered cells
- Supports manual movement and automated DFS exploration
- Terminates conversation on command or death event

### Helper Agent (Environment Oracle)

Responsibilities:
- Stores the maze matrix in memory
- Validates moves from Traveller
- Rejects blocked/out-of-bounds moves
- Detects death states (pit/wumpus)
- Returns local adjacency intelligence for valid positions
- Auto-terminates conversation when death occurs

## Maze Cell Semantics

Helper uses these semantic states:
- `safe`: navigable cell
- `blocked`: non-traversable obstacle
- `pit`: lethal hazard
- `wumpus`: lethal hazard
- `goal`: target endpoint
- `out`: out-of-bounds coordinate

Operational behavior:
- `safe` / `goal`: move accepted
- `blocked` / `out`: move rejected, position unchanged
- `pit` / `wumpus`: agent death

## Session and Mode Lifecycle

Maze mode runs inside an existing encrypted session.

### Preconditions

1. Session exists between Traveller and Helper
2. AES key is established (`keyexchange` complete)

### Start

Traveller CLI command:
- `maze_solver`

Then Traveller sends:
- `maze_solver:start`

Helper response:
- `maze_solver:ready`
- Initial adjacency snapshot for start location

### Stop

Conversation ends if either side sends:
- `command:exit_convo`

Session remains reusable for future communication.

## Message Protocol (Maze Mode)

All of the following are encrypted inside the normal `/agent/communicate/send` payload.

### Control Messages

- `maze_solver:start`
- `maze_solver:ready`
- `maze_solver:stop`
- `command:automate`
- `command:exit_convo`

### Coordinate Probe

Traveller -> Helper:
- `maze_coord:x,y`

Example:
- `maze_coord:2,3`

### Valid Move Result

Helper -> Traveller:
- `maze_adjacent:{...json...}`

Payload schema:
```json
{
  "type": "maze_adjacent",
  "origin": {"x": 2, "y": 3, "state": "safe"},
  "neighbors": [
    {"dir": "up", "x": 2, "y": 2, "state": "safe"},
    {"dir": "down", "x": 2, "y": 4, "state": "blocked"},
    {"dir": "left", "x": 1, "y": 3, "state": "safe"},
    {"dir": "right", "x": 3, "y": 3, "state": "pit"}
  ]
}
```

### Blocked/Invalid Move Result

Helper -> Traveller:
- `maze_move_blocked:{...json...}`

Payload schema:
```json
{
  "reason": "blocked",
  "attempted": {"x": 4, "y": 4},
  "current": {"x": 3, "y": 4},
  "adjacent": {
    "type": "maze_adjacent",
    "origin": {"x": 3, "y": 4, "state": "safe"},
    "neighbors": []
  }
}
```

Rule:
- Traveller position is not updated
- Map updates from `adjacent.current` context only

### Death Result

Helper -> Traveller (in order):
1. `AGENT DIED`
2. `command:exit_convo`

Rule:
- Traveller marks conversation inactive
- Maze mode ends automatically
- Matplotlib window closes

## CLI Usage

### Manual Maze Exploration

1. Start session and key exchange
2. Run `maze_solver`
3. Pick session
4. Enter coordinates in form `x,y`
5. Inspect map and continue
6. Exit with `command:exit_convo`

Coordinate format:
- `x,y` (integers)
- Example: `0,0`, `2,3`

### Automated DFS Mode

Inside `maze_solver` prompt, enter:
- `command:automate`

Behavior:
- AI runs DFS over discovered safe graph
- Explores `safe` and `goal`
- Avoids known `blocked`, `out`, `pit`, `wumpus`
- Backtracks when branch is exhausted
- Stops on goal reached, death, timeout, or conversation termination

## DFS Strategy Details

Traveller DFS maintains:
- `known_states[(x,y)]`: latest known state per coordinate
- `adjacency[(x,y)]`: discovered neighbors and states
- `visited`: explored nodes
- `stack`: DFS path/backtracking stack

Decision policy:
1. Prefer unexplored `safe` / `goal` neighbor
2. Mark hazards and blocked/out as non-traversable
3. If no forward safe move, backtrack to parent
4. Terminate when origin state is `goal`

Safety policy:
- DFS never intentionally chooses known lethal cells
- If unknown environment response indicates death, automation stops immediately

## Visualization Behavior (Traveller)

The map is rendered with matplotlib and updates from Helper payloads.

### Window Lifecycle

- Opens only when `maze_solver` starts successfully
- Stays open during active maze conversation
- Closes on:
  - Local `command:exit_convo`
  - Remote `command:exit_convo`
  - `AGENT DIED`
  - Traveller process exit

### Axis

- X increases to the right
- Y increases upward
- Y axis starts at 0 from bottom

### Legend and Symbols

- Unknown: light gray
- Safe: green-tinted cell
- Blocked: brick-colored hatched tile
- Pit: dark downward marker
- Wumpus: distinct star marker
- Goal: green triangular flag marker
- Traveller: dark circular marker with `T`

## Internal State Extensions

### Session-level fields

Used for maze mode:
- `conversation_active`
- `maze_mode`
- `maze_position` (Helper side)

### Runtime event channel (Traveller)

Per session runtime event data:
- latest message type
- latest payload
- synchronization event used by DFS wait loop

## Security Context

Maze messages inherit all secure communication guarantees from the base protocol:
- AES-GCM encrypted payloads
- Per-session sequence number validation
- Replay resistance
- Session scoping and peer binding

No plaintext maze intelligence is exchanged outside encrypted session payloads.

## Failure Handling

Handled scenarios:
- Missing/invalid coordinate format
- Blocked/out move attempts
- Lethal move (pit/wumpus)
- Parsing errors in maze payload
- Conversation closed mid-run
- Send/connect failures

Typical outcomes:
- Blocked: move rejected, continue
- Dead: auto terminate conversation
- Timeout/unexpected response: automation aborts safely

## End-to-End Flow Summary

1. Traveller enters `maze_solver`
2. Helper confirms maze mode and provides first adjacency
3. Traveller either:
   - manually sends `x,y`, or
   - sends `command:automate` for DFS
4. Helper evaluates rules and returns maze intelligence
5. Traveller updates map and chooses next step
6. On death or exit command, conversation terminates and plot closes
7. Session remains available for reuse later

## Notes for Extensions

Potential future improvements:
- A* mode (`command:auto_astar`) with heuristic to goal
- Persist discovered map per session between runs
- Multi-goal or dynamic obstacle environments
- Confidence/uncertainty overlays for partially observed maps
- Save map snapshots to file after each step

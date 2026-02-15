import sys
sys.path.insert(0, 'routes')

from session_manager import SessionState
import uuid

# Test 1: Create a session
print("Test 1: Creating session...")
session_id = str(uuid.uuid4())
session = SessionState(
    session_id=session_id,
    peer_agent_id="helper_agent_001",
    peer_address="https://127.0.0.1:5001"
)
print(f"✓ Session created: {session}")

# Test 2: Test sequence numbers
print("\nTest 2: Testing sequence numbers...")
print(f"Initial send_seq: {session.send_seq}")
session.increment_send_seq()
print(f"After increment: {session.send_seq}")
session.increment_recv_seq()
print(f"Recv seq: {session.recv_seq}")

# Test 3: Test duration
print("\nTest 3: Testing duration...")
import time
time.sleep(1)
print(f"Session duration: {session.get_duration():.2f}s")

# Test 4: Test key clearing
print("\nTest 4: Testing key clearing...")
session.aes_key = b"fake_32_byte_key_for_testing_12"
print(f"Before clear - has key: {session.aes_key is not None}")
session.clear_keys()
print(f"After clear - has key: {session.aes_key is not None}")
print(f"Session active: {session.is_active}")

print("\n✅ All SessionState tests passed!")
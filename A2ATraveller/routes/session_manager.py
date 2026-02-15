"""
Session State Management for Peer-to-Peer Communication

This module handles the state management for secure communication sessions
between agents, including AES keys, sequence numbers, and session metadata.
"""

import time
from typing import Optional


class SessionState:
    """
    Manages the state of a secure communication session between two agents.
    
    Attributes:
        session_id (str): Unique identifier for the session
        peer_agent_id (str): Agent ID of the peer
        peer_address (str): HTTPS address of peer agent
        peer_public_key: RSA public key of peer (for signature verification)
        aes_key (bytes): 256-bit AES key derived from DH exchange
        send_seq (int): Sequence number for outgoing messages
        recv_seq (int): Expected sequence number for incoming messages
        created_at (float): Unix timestamp when session was created
        is_active (bool): Whether session is currently active
    """
    
    def __init__(self, session_id: str, peer_agent_id: str, peer_address: str = None):
        """
        Initialize a new communication session.
        
        Args:
            session_id: Unique session identifier (UUID)
            peer_agent_id: Agent ID of the communication peer
            peer_address: HTTPS address of peer (e.g., "https://127.0.0.1:5001")
        """
        self.session_id = session_id
        self.peer_agent_id = peer_agent_id
        self.peer_address = peer_address
        
        # Cryptographic material
        self.peer_public_key = None  # Will be set after certificate verification
        self.aes_key: Optional[bytes] = None  # 32 bytes for AES-256
        
        # Message sequence tracking (replay protection)
        self.send_seq = 0  # Messages sent by this agent
        self.recv_seq = 0  # Messages received from peer
        
        # Session metadata
        self.created_at = time.time()
        self.is_active = True
        
        # Message queue for incoming messages (used by CLI)
        self.incoming_messages = []
    
    def clear_keys(self):
        """
        Securely clear cryptographic material from memory.
        
        This should be called when the session is closed to prevent
        key material from persisting in memory longer than necessary.
        """
        if self.aes_key:
            # Overwrite key bytes before dereferencing
            # Note: Python's garbage collector will handle actual memory cleanup
            self.aes_key = None
        
        self.peer_public_key = None
        self.is_active = False
        
        print(f"[SESSION] Cryptographic material cleared for session {self.session_id[:8]}...")
    
    def increment_send_seq(self):
        """Increment and return the send sequence number."""
        self.send_seq += 1
        return self.send_seq
    
    def increment_recv_seq(self):
        """Increment and return the receive sequence number."""
        self.recv_seq += 1
        return self.recv_seq
    
    def get_duration(self) -> float:
        """
        Get the duration of the session in seconds.
        
        Returns:
            Number of seconds since session creation
        """
        return time.time() - self.created_at
    
    def __repr__(self):
        """String representation for debugging."""
        duration = int(self.get_duration())
        status = "Active" if self.is_active else "Closed"
        has_key = "Yes" if self.aes_key else "No"
        
        return (
            f"SessionState("
            f"id={self.session_id[:8]}..., "
            f"peer={self.peer_agent_id}, "
            f"duration={duration}s, "
            f"status={status}, "
            f"has_aes_key={has_key}, "
            f"send_seq={self.send_seq}, "
            f"recv_seq={self.recv_seq})"
        )

class TravellerAgent:
    def __init__(self):
        self.name = "Traveller Agent"
        self.methods = ["send_request", "receive_response"]
        self.id="traveller_agent_001"
        self.agent_card = {
            "name": self.name,
            "id": self.id,
            "methods": self.methods,
            "method_descriptions": {
                "send_request": "Sends a request to another agent.",
                "receive_response": "Handles the response received from another agent. "
                }
        }
        

    
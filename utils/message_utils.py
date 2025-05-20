# In a new file: utils/message_utils.py
import json
from datetime import datetime

def create_standard_message(message_type, content, metadata=None):
    """
    Create a standardized message format for agent communication.
    
    Parameters:
    - message_type: Type of message (plan, request, response, error, result)
    - content: The main message content
    - metadata: Additional metadata for the message
    
    Returns:
    - Standardized message dictionary
    """
    if metadata is None:
        metadata = {}
    
    return {
        "type": message_type,
        "timestamp": datetime.now().isoformat(),
        "content": content,
        "metadata": metadata
    }

def create_plan_message(target, plan):
    """Create a standardized plan message."""
    return create_standard_message(
        "plan",
        f"Execution plan for {target}",
        {
            "target": target,
            "plan": plan
        }
    )

def create_request_message(from_agent, to_agent, action, parameters=None):
    """Create a standardized request message."""
    if parameters is None:
        parameters = {}
    
    return create_standard_message(
        "request",
        f"Request from {from_agent} to {to_agent}: {action}",
        {
            "from": from_agent,
            "to": to_agent,
            "action": action,
            "parameters": parameters
        }
    )

def create_response_message(from_agent, to_agent, action, result, success=True):
    """Create a standardized response message."""
    return create_standard_message(
        "response",
        f"Response from {from_agent} to {to_agent}: {action}",
        {
            "from": from_agent,
            "to": to_agent,
            "action": action,
            "success": success,
            "result": result
        }
    )

def create_error_message(from_agent, to_agent, action, error):
    """Create a standardized error message."""
    return create_standard_message(
        "error",
        f"Error from {from_agent} to {to_agent}: {action}",
        {
            "from": from_agent,
            "to": to_agent,
            "action": action,
            "error": error
        }
    )

def create_result_message(agent, action, result):
    """Create a standardized result message."""
    return create_standard_message(
        "result",
        f"Result from {agent}: {action}",
        {
            "agent": agent,
            "action": action,
            "result": result
        }
    )

def message_to_string(message):
    """Convert a message to a string for display."""
    return json.dumps(message, indent=2)

def message_to_chat_message(message):
    """Convert a standardized message to a chat message."""
    if message["type"] == "plan":
        return f"📝 PLAN: {message['content']}"
    elif message["type"] == "request":
        return f"📤 REQUEST [{message['metadata']['from']} → {message['metadata']['to']}]: {message['metadata']['action']}"
    elif message["type"] == "response":
        status = "✅" if message['metadata']['success'] else "❌"
        return f"📥 RESPONSE {status} [{message['metadata']['from']} → {message['metadata']['to']}]: {message['metadata']['action']}"
    elif message["type"] == "error":
        return f"❌ ERROR [{message['metadata']['from']} → {message['metadata']['to']}]: {message['metadata']['error']}"
    elif message["type"] == "result":
        return f"🏆 RESULT [{message['metadata']['agent']}]: {message['metadata']['action']}"
    else:
        return f"💬 MESSAGE: {message['content']}"

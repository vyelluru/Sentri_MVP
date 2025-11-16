"""
Base Model Adapter - Abstract interface for all model providers
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Message:
    """Represents a message in the conversation"""
    role: str  # 'system', 'user', 'assistant'
    content: str


@dataclass
class ToolCall:
    """Represents a tool call made by the model"""
    tool_name: str
    parameters: Dict[str, Any]
    tool_call_id: Optional[str] = None  # Some models provide IDs


@dataclass
class ModelResponse:
    """Standardized response from any model"""
    content: str  # Text response from model
    tool_calls: List[ToolCall]  # Any tools the model tried to call
    raw_response: Any  # Original API response for debugging
    finish_reason: str  # 'stop', 'tool_calls', 'length', etc.


class BaseModelAdapter(ABC):
    """
    Abstract base class for model adapters
    All model-specific adapters must implement these methods
    """
    
    def __init__(self, api_key: str, model: str, base_url: Optional[str] = None):
        """
        Initialize adapter
        
        Args:
            api_key: API key for the provider
            model: Model name/identifier
            base_url: Optional custom API endpoint
        """
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
    
    @abstractmethod
    def format_tools(self, tools: List[Dict[str, Any]]) -> Any:
        """
        Convert tools from YAML format to provider-specific format
        
        Args:
            tools: List of tool definitions from agent manifest
            
        Returns:
            Provider-specific tool format
        """
        pass
    
    @abstractmethod
    def call_model(
        self,
        messages: List[Message],
        tools: Any,
        temperature: float = 0.7,
        max_tokens: int = 1000
    ) -> ModelResponse:
        """
        Call the model API
        
        Args:
            messages: Conversation history
            tools: Formatted tool definitions
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            ModelResponse: Standardized response
        """
        pass
    
    @abstractmethod
    def parse_tool_calls(self, response: Any) -> List[ToolCall]:
        """
        Extract tool calls from provider-specific response
        
        Args:
            response: Raw API response
            
        Returns:
            List of ToolCall objects
        """
        pass
    
    def execute_attack(
        self,
        system_prompt: str,
        attack_prompt: str,
        tools: List[Dict[str, Any]],
        temperature: float = 0.7
    ) -> ModelResponse:
        """
        Execute a single attack against the agent
        
        Args:
            system_prompt: Agent's system prompt
            attack_prompt: Attack message
            tools: Tool definitions
            temperature: Sampling temperature
            
        Returns:
            ModelResponse: What the model tried to do
        """
        # Build message history
        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=attack_prompt)
        ]
        
        # Format tools for this provider
        formatted_tools = self.format_tools(tools)
        
        # Call model
        return self.call_model(messages, formatted_tools, temperature)


# Helper functions for adapters

def convert_parameter_type(param_type: str) -> str:
    """Convert our parameter types to JSON Schema types"""
    type_mapping = {
        "string": "string",
        "number": "number",
        "boolean": "boolean",
        "array": "array",
        "object": "object"
    }
    return type_mapping.get(param_type, "string")


def build_json_schema_for_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a tool definition to JSON Schema format
    (Used by most model providers)
    
    Args:
        tool: Tool definition from manifest
        
    Returns:
        JSON Schema compatible tool definition
    """
    properties = {}
    required = []
    
    for param in tool.get('parameters', []):
        param_schema = {
            "type": convert_parameter_type(param['type']),
            "description": param['description']
        }
        
        # Add enum if specified
        if 'enum' in param and param['enum']:
            param_schema['enum'] = param['enum']
        
        properties[param['name']] = param_schema
        
        if param.get('required', True):
            required.append(param['name'])
    
    return {
        "type": "function",
        "function": {
            "name": tool['name'],
            "description": tool['description'],
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }
    }
"""
OpenAI Model Adapter - Handles OpenAI API calls with function calling
"""

from typing import List, Dict, Any, Optional
import json

try:
    from openai import OpenAI
except ImportError:
    print("OpenAI library not installed. Run: pip install openai")
    OpenAI = None

# Import base classes (in real implementation)
from adapter import BaseModelAdapter, Message, ToolCall, ModelResponse, build_json_schema_for_tool


class OpenAIAdapter:
    """Adapter for OpenAI models (GPT-4, GPT-3.5, etc.)"""
    
    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: Optional[str] = None):
        """
        Initialize OpenAI adapter
        
        Args:
            api_key: OpenAI API key
            model: Model name (gpt-4o, gpt-4-turbo, etc.)
            base_url: Optional custom endpoint (for Azure)
        """
        if OpenAI is None:
            raise ImportError("openai package required. Install with: pip install openai")
        
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        
        # Initialize OpenAI client
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        
        self.client = OpenAI(**client_kwargs)
    
    def format_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert tools to OpenAI function calling format
        
        Args:
            tools: List of tool definitions from manifest
            
        Returns:
            OpenAI-formatted tool definitions
        """
        formatted_tools = []
        
        for tool in tools:
            # Build parameters schema
            properties = {}
            required = []
            
            for param in tool.get('parameters', []):
                properties[param['name']] = {
                    "type": param['type'],
                    "description": param['description']
                }
                
                # Add enum if present
                if 'enum' in param and param['enum']:
                    properties[param['name']]['enum'] = param['enum']
                
                if param.get('required', True):
                    required.append(param['name'])
            
            # OpenAI function format
            formatted_tool = {
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
            
            formatted_tools.append(formatted_tool)
        
        return formatted_tools
    
    def call_model(
        self,
        messages: List[Message],
        tools: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 1000
    ) -> ModelResponse:
        """
        Call OpenAI API with function calling
        
        Args:
            messages: Conversation history
            tools: OpenAI-formatted tool definitions
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            
        Returns:
            ModelResponse with any tool calls
        """
        # Convert Message objects to OpenAI format
        openai_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Make API call
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=openai_messages,
                tools=tools if tools else None,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            # Parse response
            message = response.choices[0].message
            finish_reason = response.choices[0].finish_reason
            
            # Extract content
            content = message.content or ""
            
            # Extract tool calls
            tool_calls = []
            if message.tool_calls:
                tool_calls = self.parse_tool_calls(message.tool_calls)
            
            return ModelResponse(
                content=content,
                tool_calls=tool_calls,
                raw_response=response,
                finish_reason=finish_reason
            )
            
        except Exception as e:
            # Return error as response
            return ModelResponse(
                content=f"Error calling OpenAI API: {str(e)}",
                tool_calls=[],
                raw_response=None,
                finish_reason="error"
            )
    
    def parse_tool_calls(self, tool_calls_raw: Any) -> List[ToolCall]:
        """
        Parse tool calls from OpenAI response
        
        Args:
            tool_calls_raw: Raw tool_calls from OpenAI response
            
        Returns:
            List of ToolCall objects
        """
        parsed_calls = []
        
        for call in tool_calls_raw:
            try:
                # Parse arguments (they come as JSON string)
                arguments = json.loads(call.function.arguments)
                
                parsed_calls.append(ToolCall(
                    tool_name=call.function.name,
                    parameters=arguments,
                    tool_call_id=call.id
                ))
            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse tool call arguments: {e}")
                continue
        
        return parsed_calls
    
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
            tools: Tool definitions from manifest
            temperature: Sampling temperature
            
        Returns:
            ModelResponse: What the model tried to do
        """
        # Build messages
        messages = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=attack_prompt)
        ]
        
        # Format tools
        formatted_tools = self.format_tools(tools)
        
        # Call model
        return self.call_model(messages, formatted_tools, temperature)


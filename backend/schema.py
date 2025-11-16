"""
Agent Security Platform - Schema Definitions
Defines the structure of agent manifests using Pydantic for validation
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, validator
from enum import Enum


class RiskLevel(str, Enum):
    """Risk levels for tools"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelProvider(str, Enum):
    """Supported model providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"


class ParameterType(str, Enum):
    """Supported parameter types"""
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class ToolParameter(BaseModel):
    """Definition of a tool parameter"""
    name: str
    type: ParameterType
    description: str
    required: bool = True
    enum: Optional[List[str]] = None  # For restricted values
    
    class Config:
        use_enum_values = True


class Tool(BaseModel):
    """Tool/function that the agent can call"""
    name: str = Field(..., description="Tool name (must be valid function name)")
    description: str = Field(..., description="What the tool does")
    parameters: List[ToolParameter] = Field(default_factory=list)
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    requires_confirmation: bool = Field(default=False, description="Should require user confirmation")
    
    @validator('name')
    def validate_tool_name(cls, v):
        """Ensure tool name is a valid identifier"""
        if not v.replace('_', '').isalnum():
            raise ValueError(f"Tool name must be alphanumeric with underscores: {v}")
        return v
    
    class Config:
        use_enum_values = True


class ModelConfig(BaseModel):
    """Configuration for the LLM model"""
    provider: ModelProvider
    model: str = Field(..., description="Model name (e.g., gpt-4o, claude-3-5-sonnet-20241022)")
    api_key_env: str = Field(..., description="Environment variable name for API key")
    base_url: Optional[str] = Field(None, description="Custom API endpoint (for Azure, etc.)")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1000, ge=1)
    
    class Config:
        use_enum_values = True


class SafetyRule(BaseModel):
    """Safety rules and restrictions"""
    denied_patterns: List[str] = Field(
        default_factory=list,
        description="Regex patterns for denied tool parameters"
    )
    sensitive_paths: List[str] = Field(
        default_factory=list,
        description="File paths that should never be accessed"
    )
    require_confirmation_for: List[str] = Field(
        default_factory=list,
        description="Tool names that always need confirmation"
    )
    max_tool_calls_per_request: int = Field(
        default=10,
        description="Maximum number of tool calls in one request"
    )


class AgentManifest(BaseModel):
    """Complete agent specification"""
    name: str = Field(..., description="Agent name")
    description: Optional[str] = Field(None, description="What the agent does")
    version: str = Field(default="1.0.0")
    
    model: ModelConfig
    system_prompt: str = Field(..., min_length=10)
    tools: List[Tool] = Field(..., min_items=1)
    safety_rules: Optional[SafetyRule] = Field(default_factory=SafetyRule)
    
    @validator('tools')
    def validate_unique_tool_names(cls, v):
        """Ensure no duplicate tool names"""
        names = [tool.name for tool in v]
        if len(names) != len(set(names)):
            raise ValueError("Tool names must be unique")
        return v

"""
YAML Parser - Load and validate agent manifests
"""

import yaml
import os
from pathlib import Path
from typing import Optional
from pydantic import ValidationError

# Import schemas (assumes agent_schema.py is in same package)
# from .schemas.agent_manifest import AgentManifest, ModelConfig, Tool

# For standalone testing, we'll define a minimal version here
# In real implementation, import from agent_schema.py


class ParserError(Exception):
    """Custom exception for parser errors"""
    pass


class YAMLParser:
    """Parses and validates agent YAML manifests"""
    
    def __init__(self):
        self.manifest = None
    
    def load_from_file(self, file_path: str):
        """
        Load agent manifest from YAML file
        
        Args:
            file_path: Path to agent.yaml file
            
        Returns:
            AgentManifest: Validated manifest object
            
        Raises:
            ParserError: If file doesn't exist or YAML is invalid
            ValidationError: If manifest doesn't match schema
        """
        path = Path(file_path)
        
        # Check file exists
        if not path.exists():
            raise ParserError(f"File not found: {file_path}")
        
        # Check file extension
        if path.suffix not in ['.yaml', '.yml']:
            raise ParserError(f"File must be .yaml or .yml, got: {path.suffix}")
        
        # Load YAML
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ParserError(f"Invalid YAML syntax: {e}")
        
        # Validate against schema
        return self.validate_manifest(data)
    
    def load_from_string(self, yaml_string: str):
        """
        Load agent manifest from YAML string
        
        Args:
            yaml_string: YAML content as string
            
        Returns:
            AgentManifest: Validated manifest object
        """
        try:
            data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise ParserError(f"Invalid YAML syntax: {e}")
        
        return self.validate_manifest(data)
    
    def validate_manifest(self, data: dict):
        """
        Validate manifest data against Pydantic schema
        
        Args:
            data: Dictionary from parsed YAML
            
        Returns:
            AgentManifest: Validated manifest object
            
        Raises:
            ValidationError: If validation fails
        """
        # In real implementation, this would use:
        # return AgentManifest(**data)
        
        # For now, do basic validation
        required_fields = ['name', 'model', 'system_prompt', 'tools']
        for field in required_fields:
            if field not in data:
                raise ParserError(f"Missing required field: {field}")
        
        # Basic model validation
        if 'provider' not in data['model']:
            raise ParserError("model.provider is required")
        
        if 'model' not in data['model']:
            raise ParserError("model.model is required")
        
        if 'api_key_env' not in data['model']:
            raise ParserError("model.api_key_env is required")
        
        # Basic tools validation
        if not isinstance(data['tools'], list) or len(data['tools']) == 0:
            raise ParserError("At least one tool must be defined")
        
        for i, tool in enumerate(data['tools']):
            if 'name' not in tool:
                raise ParserError(f"Tool {i} missing 'name' field")
            if 'description' not in tool:
                raise ParserError(f"Tool {tool.get('name', i)} missing 'description' field")
        
        # Store validated manifest
        self.manifest = data
        return data
    
    def get_api_credentials(self):
        """
        Extract API credentials from environment
        
        Returns:
            dict: API credentials
            
        Raises:
            ParserError: If API key not found in environment
        """
        if not self.manifest:
            raise ParserError("No manifest loaded")
        
        api_key_env = self.manifest['model']['api_key_env']
        api_key = os.getenv(api_key_env)
        
        if not api_key:
            raise ParserError(
                f"API key not found in environment variable: {api_key_env}"
            )
        
        return {
            'provider': self.manifest['model']['provider'],
            'api_key': api_key,
            'base_url': self.manifest['model'].get('base_url')
        }
    
    def get_tools(self):
        """Get list of tools from manifest"""
        if not self.manifest:
            raise ParserError("No manifest loaded")
        return self.manifest['tools']
    
    def get_system_prompt(self):
        """Get system prompt from manifest"""
        if not self.manifest:
            raise ParserError("No manifest loaded")
        return self.manifest['system_prompt']
    
    def get_safety_rules(self):
        """Get safety rules from manifest"""
        if not self.manifest:
            raise ParserError("No manifest loaded")
        return self.manifest.get('safety_rules', {})

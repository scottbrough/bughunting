# secure_config.py - Example of securely handling API keys

import os
import json
import getpass
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

def get_api_key(service_name="openai"):
    """
    Get API key from environment variables or prompt user.
    Never store keys directly in code.
    """
    # First try to get from environment variable
    env_var_name = f"{service_name.upper()}_API_KEY"
    api_key = os.getenv(env_var_name)
    
    if api_key:
        return api_key
    
    # If not in environment, check .env file
    dotenv_path = Path('.env')
    if dotenv_path.exists():
        # Already loaded by load_dotenv()
        api_key = os.getenv(env_var_name)
        if api_key:
            return api_key
    
    # As a last resort, prompt user (not recommended for production)
    print(f"No {service_name} API key found in environment or .env file.")
    api_key = getpass.getpass(f"Enter your {service_name} API key: ")
    
    # Store in .env file for future use
    if api_key:
        with open(dotenv_path, 'a') as f:
            f.write(f"\n{env_var_name}={api_key}")
        print(f"API key saved to .env file. This file is ignored by git.")
    
    return api_key

def setup_config_file(filename="config/config.json", template_file="config/config.template.json"):
    """
    Set up configuration file from template, prompting for API keys as needed.
    Never include actual API keys in template files that might be committed.
    """
    # Create config directory if it doesn't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Check if config file already exists
    if os.path.exists(filename):
        print(f"Config file {filename} already exists. Skipping setup.")
        return
    
    # Check if template exists
    if not os.path.exists(template_file):
        # Create basic template
        template = {
            "model_configs": {
                "gpt-4o": {
                    "model": "gpt-4o",
                    "api_key": "YOUR_API_KEY_HERE"
                }
            },
            "default_model": "gpt-4o"
        }
    else:
        # Load template
        with open(template_file, 'r') as f:
            template = json.load(f)
    
    # Replace API key placeholders with actual keys
    if "model_configs" in template:
        for model_name, config in template["model_configs"].items():
            if "api_key" in config and config["api_key"] in ["YOUR_API_KEY_HERE", ""]:
                # Replace with actual key
                config["api_key"] = get_api_key("openai")
    
    # Save config file
    with open(filename, 'w') as f:
        json.dump(template, f, indent=2)
    
    print(f"Config file created at {filename}. This file is ignored by git.")

# Example usage
if __name__ == "__main__":
    # Set up config file
    setup_config_file()
    
    # How to use in your code
    api_key = get_api_key("openai")
    print(f"Using API key: {api_key[:5]}...{api_key[-3:]}")

# In a new file: utils/config_loader.py
import os
import json
from dotenv import load_dotenv

def load_config():
    """Load configuration from config.json and environment variables."""
    load_dotenv()
    
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.json')
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {
            "model_configs": {},
            "default_model": "gpt-3.5-turbo"
        }
    
    # Override with environment variables if present
    if os.getenv("OPENAI_API_KEY"):
        for model_config in config["model_configs"].values():
            model_config["api_key"] = os.getenv("OPENAI_API_KEY")
    
    return config

def get_model_config(model_name=None):
    """Get configuration for a specific model or default model."""
    config = load_config()
    if model_name and model_name in config["model_configs"]:
        return config["model_configs"][model_name]
    return config["model_configs"][config["default_model"]]

#!/usr/bin/env python3
"""
Enhanced Cybersecurity Platform - Main Entry Point
Plateforme de cybersécurité avec outils Kali Linux et IA
"""

import logging
import sys
from pathlib import Path

from core.platform import CybersecurityPlatform, create_platform
from config.default_config import DEFAULT_CONFIG, PRODUCTION_CONFIG, DEVELOPMENT_CONFIG


def setup_logging(config: dict):
    """Configure logging"""
    logging_config = config.get('logging', {})
    
    logging.basicConfig(
        level=getattr(logging, logging_config.get('level', 'INFO')),
        format=logging_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(logging_config.get('file', 'platform.log'))
        ]
    )


def main():
    """Main entry point"""
    logger = logging.getLogger(__name__)
    
    try:
        env = sys.argv[1] if len(sys.argv) > 1 else 'default'
        
        if env == 'production':
            config = PRODUCTION_CONFIG
        elif env == 'development':
            config = DEVELOPMENT_CONFIG
        else:
            config = DEFAULT_CONFIG
        
        setup_logging(config)
        
        logger.info("=" * 80)
        logger.info("Enhanced Cybersecurity Platform - Starting")
        logger.info(f"Environment: {env}")
        logger.info("=" * 80)
        
        platform = create_platform(config)
        
        logger.info("Platform initialized successfully")
        logger.info(f"Tools available: {', '.join(platform.list_tools())}")
        logger.info(f"AI models available: {', '.join(platform.list_ai_models())}")
        
        platform.start()
        
        logger.info("Platform started successfully")
        logger.info("Press Ctrl+C to stop...")
        
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\nShutdown signal received...")
        
        platform.stop()
        
        logger.info("Platform stopped successfully")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

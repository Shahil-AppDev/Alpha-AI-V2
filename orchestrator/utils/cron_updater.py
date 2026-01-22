#!/usr/bin/env python3
"""
Cron Job Script for Security Tools Updates
Run this script daily to update security tools
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.security_skill_manager import SecuritySkillManager


def setup_logging():
    """Setup logging for cron job"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/orchestrator/security_updates.log'),
            logging.StreamHandler()
        ]
    )


def main():
    """Main entry point for cron job"""
    logger = logging.getLogger(__name__)
    
    try:
        setup_logging()
        
        logger.info("=" * 80)
        logger.info("Security Tools Update - Starting")
        logger.info("=" * 80)
        
        manager = SecuritySkillManager()
        
        logger.info("Checking for updates...")
        check_results = manager.check_tool_updates()
        
        if check_results.get('updates_available'):
            logger.info(f"Found {len(check_results['updates_available'])} updates available")
            
            for update in check_results['updates_available']:
                logger.info(f"  - {update['tool']}: {update['installed']} -> {update['candidate']}")
            
            logger.info("Applying updates...")
            update_results = manager.update_tool_database()
            
            if update_results['success']:
                logger.info(f"Successfully updated {len(update_results['tools_updated'])} tools")
                
                if update_results['tools_failed']:
                    logger.warning(f"Failed to update {len(update_results['tools_failed'])} tools")
                    for failed in update_results['tools_failed']:
                        logger.warning(f"  - {failed['tool']}: {failed['error']}")
            else:
                logger.error(f"Update failed: {update_results.get('error', 'Unknown error')}")
                sys.exit(1)
        else:
            logger.info("All tools are up to date")
        
        logger.info("=" * 80)
        logger.info("Security Tools Update - Completed")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

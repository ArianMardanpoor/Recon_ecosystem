#!/usr/bin/env python3
import subprocess
import logging
from typing import List, Optional
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

def run_command_safe(command_args, shell=False, timeout=60):
    """
    اجرای امن دستورات با استفاده از لیست آرگومان‌ها
    """
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=timeout  # استفاده از تایم‌اوت متغیر
        )
        
        if result.returncode != 0:
            # دیباگ لاگ برای بررسی خطاهای بی‌صدا
            cmd_str = ' '.join(command_args) if isinstance(command_args, list) else str(command_args)
            stderr_out = result.stderr[:1000] if result.stderr else "No stderr output"
            print(f"[!] Command failed (code {result.returncode}): {cmd_str}")
            print(f"[!] Stderr (first 1000 chars): {stderr_out}")
            return None
        
        return result.stdout.splitlines()
    
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout} seconds")
        return None
    except Exception as e:
        print(f"Exception: {e}")
        return None

def run_command_with_input(command_args: List[str], input_string: str, timeout: int = 60) -> Optional[str]:
    """
    اجرای دستور با دریافت ورودی از stdin.
    """
    try:
        result = subprocess.run(
            command_args,
            input=input_string,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.error(f"Command failed: {' '.join(command_args)} | Error: {result.stderr.strip()}")
            return None
            
        return result.stdout
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout ({timeout}s) expired for command: {' '.join(command_args)}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error running piped command: {e}")
        return None
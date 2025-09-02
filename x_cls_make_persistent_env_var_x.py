from __future__ import annotations
import subprocess
import sys
from typing import Optional

class x_cls_make_persistent_env_var_x:
    """
    Generic persistent environment variable setter for Windows (User scope).
    Usage: Only supports usage 1 (set and verify a single variable).
    """
    def __init__(self, var: str, value: str, quiet: bool = False) -> None:
        self.var = var
        self.value = value
        self.quiet = quiet

    def set_user_env(self) -> bool:
        # Set environment variable in User scope (Windows registry)
        cmd = f'[Environment]::SetEnvironmentVariable("{self.var}", "{self.value}", "User")'
        result = self.run_powershell(cmd)
        return result.returncode == 0

    def get_user_env(self) -> Optional[str]:
        # Get environment variable from User scope
        cmd = f'[Environment]::GetEnvironmentVariable("{self.var}", "User")'
        result = self.run_powershell(cmd)
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        return value or None

    @staticmethod
    def run_powershell(command: str) -> subprocess.CompletedProcess:
        # Run a PowerShell command and return the completed process
        return subprocess.run([
            "powershell", "-Command", command
        ], capture_output=True, text=True)

    def run(self) -> bool:
        # Set and verify the variable
        ok_set = self.set_user_env()
        verified = self.get_user_env()
        if not self.quiet:
            print(f"\nResults:")
            print(f"- {self.var} set: {'yes' if ok_set else 'no'} | stored: {verified!r}")
            print("\nNote: Open a NEW PowerShell window for these to be available to your session.")
        return ok_set and verified == self.value

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Set a persistent user environment variable (Windows). Only usage 1 supported.")
    parser.add_argument("--var", required=True, help="Name of the environment variable.")
    parser.add_argument("--value", required=True, help="Value to set.")
    parser.add_argument("--quiet", action="store_true", help="Reduce output.")
    args = parser.parse_args()
    exit_code = 0 if x_cls_make_persistent_env_var_x(args.var, args.value, args.quiet).run() else 1
    sys.exit(exit_code)
##python c:\x_cloned_repos_x\x_legatus_tactica_core_x\x_code_x\x_cls_make_persistent_env_var_x.py --var "YOUR_VAR_NAME" --value "YOUR_VALUE"
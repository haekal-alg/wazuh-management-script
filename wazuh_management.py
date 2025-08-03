#!/usr/bin/env python3
"""
Wazuh SOCFortress Configuration Script
Configures Wazuh with SOCFortress ruleset
"""

import os
import sys
import argparse
import subprocess
import shutil
import time
import glob
from datetime import datetime
from pathlib import Path


class WazuhConfigurator:
    def __init__(self):
        self.skip_confirmation = False
        self.debug = False
        self.sys_type = None
        
    def logger(self, message, level="INFO"):
        """Logger function for consistent output formatting"""
        now = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
        print(f"{now} {level}: {message}")
        
    def log_error(self, message):
        """Log error message"""
        self.logger(message, "ERROR")
        
    def log_warning(self, message):
        """Log warning message"""
        self.logger(message, "WARNING")
        
    def detect_package_manager(self):
        """Determine package manager"""
        if shutil.which('yum'):
            return 'yum'
        elif shutil.which('zypper'):
            return 'zypper'
        elif shutil.which('apt-get'):
            return 'apt-get'
        else:
            self.log_error("Unable to determine package manager. Exiting.")
            sys.exit(1)
            
    def check_dependencies(self):
        """Check for required dependencies"""
        if not shutil.which('git'):
            self.log_error(f"git package could not be found. Please install with {self.sys_type} install git.")
            sys.exit(1)
        self.logger("Git package found. Continuing...")
        
    def check_architecture(self):
        """Check system architecture"""
        import platform
        if platform.machine() != 'x86_64':
            self.log_error("Incompatible system. This script must be run on a 64-bit system.")
            sys.exit(1)
            
    def run_command(self, cmd, shell=True, capture_output=False):
        """Run system command with optional debug output"""
        try:
            if self.debug:
                self.logger(f"Running command: {cmd}")
            
            result = subprocess.run(
                cmd, 
                shell=shell, 
                capture_output=capture_output,
                text=True,
                check=True
            )
            return result
        except subprocess.CalledProcessError as e:
            if self.debug:
                self.log_error(f"Command failed: {cmd}")
                self.log_error(f"Error: {e}")
            raise
            
    def restart_service(self, service_name):
        """Restart service with appropriate method"""
        try:
            # Try systemctl first
            if shutil.which('systemctl'):
                self.logger(f"Restarting {service_name} using systemd...")
                self.run_command(f"systemctl restart {service_name}.service")
            # Try service command
            elif shutil.which('service'):
                self.logger(f"Restarting {service_name} using service...")
                self.run_command(f"service {service_name} restart")
            # Try init script
            elif os.path.isfile(f"/etc/rc.d/init.d/{service_name}"):
                self.logger(f"Restarting {service_name} using init script...")
                self.run_command(f"/etc/rc.d/init.d/{service_name} start")
            else:
                self.log_error(f"{service_name.capitalize()} could not restart. No service manager found on the system.")
                return False
                
            self.logger(f"{service_name.capitalize()} restarted successfully")
            return True
            
        except subprocess.CalledProcessError:
            self.log_error(f"{service_name.capitalize()} could not be restarted. Please check /var/ossec/logs/ossec.log for details.")
            return False
            
    def restore_backup(self):
        """Restore backup rules in case of failure"""
        self.log_error("Attempting to restore backed up rules...")
        try:
            # Copy backup files back to rules directory
            backup_files = glob.glob('/tmp/wazuh_rules_backup/*')
            for file in backup_files:
                shutil.copy2(file, '/var/ossec/etc/rules/')
            
            # Copy backup files back to decoders directory if backup exists
            backup_decoders = glob.glob('/tmp/wazuh_decoders_backup/*')
            for file in backup_decoders:
                shutil.copy2(file, '/var/ossec/etc/decoders/')
                
            # Copy backup files back to lists directory if backup exists
            backup_lists = glob.glob('/tmp/wazuh_lists_backup/*')
            for file in backup_lists:
                shutil.copy2(file, '/var/ossec/etc/lists/')
            
            # Set permissions
            self.run_command("chown -R wazuh:wazuh /var/ossec/etc/rules/*")
            self.run_command("chmod -R 660 /var/ossec/etc/rules/*")
            
            if os.path.exists('/var/ossec/etc/decoders'):
                self.run_command("chown -R wazuh:wazuh /var/ossec/etc/decoders/*")
                self.run_command("chmod -R 660 /var/ossec/etc/decoders/*")
                
            if os.path.exists('/var/ossec/etc/lists'):
                self.run_command("chown -R wazuh:wazuh /var/ossec/etc/lists/*")
                self.run_command("chmod -R 660 /var/ossec/etc/lists/*")
            
            # Restart service
            self.restart_service("wazuh-manager")
            
            # Cleanup
            shutil.rmtree('/tmp/Wazuh-Rules', ignore_errors=True)
            
        except Exception as e:
            self.log_error(f"Failed to restore backup: {e}")
            
    def health_check(self):
        """Perform health check on Wazuh manager"""
        self.logger("Performing a health check")
        
        try:
            os.chdir('/var/ossec')
            
            if not self.restart_service("wazuh-manager"):
                return False
                
            # Wait for service to fully start
            time.sleep(20)
            
            # Check service status
            result = self.run_command(
                "/var/ossec/bin/wazuh-control status", 
                capture_output=True
            )
            
            if 'wazuh-logcollector not running...' in result.stdout:
                self.log_error("Wazuh-Manager Service is not healthy. Please check /var/ossec/logs/ossec.log for details.")
                return False
            else:
                self.logger("Wazuh-Manager Service is healthy. Thanks for checking us out :)")
                self.logger("Get started with our free-for-life tier here: https://www.socfortress.co/trial.html Happy Defending!")
                shutil.rmtree('/tmp/Wazuh-Rules', ignore_errors=True)
                return True
                
        except Exception as e:
            self.log_error(f"Health check failed: {e}")
            return False
            
    def move_repo_files(self, repo_path):
        """Move files from cloned repository to appropriate Wazuh directories"""
        wazuh_repo_path = os.path.join(repo_path, 'wazuh')
        
        if not os.path.exists(wazuh_repo_path):
            self.log_error(f"Wazuh directory not found in repository: {wazuh_repo_path}")
            return False
            
        try:
            # Move rules files
            rules_src = os.path.join(wazuh_repo_path, 'rules')
            if os.path.exists(rules_src):
                self.logger("Moving rules files to /var/ossec/etc/rules/")
                rules_files = glob.glob(os.path.join(rules_src, '*'))
                for file_path in rules_files:
                    if os.path.isfile(file_path):
                        filename = os.path.basename(file_path)
                        dest_path = f"/var/ossec/etc/rules/{filename}"
                        shutil.copy2(file_path, dest_path)
                        self.logger(f"Moved rule: {filename}")
            else:
                self.log_warning("Rules directory not found in repository")
                
            # Move decoder files
            decoders_src = os.path.join(wazuh_repo_path, 'decoders')
            if os.path.exists(decoders_src):
                self.logger("Moving decoder files to /var/ossec/etc/decoders/")
                decoder_files = glob.glob(os.path.join(decoders_src, '*'))
                for file_path in decoder_files:
                    if os.path.isfile(file_path):
                        filename = os.path.basename(file_path)
                        dest_path = f"/var/ossec/etc/decoders/{filename}"
                        shutil.copy2(file_path, dest_path)
                        self.logger(f"Moved decoder: {filename}")
            else:
                self.log_warning("Decoders directory not found in repository")
                
            # Move list files
            lists_src = os.path.join(wazuh_repo_path, 'lists')
            if os.path.exists(lists_src):
                self.logger("Moving list files to /var/ossec/etc/lists/")
                # Create lists directory if it doesn't exist
                os.makedirs('/var/ossec/etc/lists', exist_ok=True)
                list_files = glob.glob(os.path.join(lists_src, '*'))
                for file_path in list_files:
                    if os.path.isfile(file_path):
                        filename = os.path.basename(file_path)
                        dest_path = f"/var/ossec/etc/lists/{filename}"
                        shutil.copy2(file_path, dest_path)
                        self.logger(f"Moved list: {filename}")
            else:
                self.log_warning("Lists directory not found in repository")
                
            return True
            
        except Exception as e:
            self.log_error(f"Failed to move repository files: {e}")
            return False
                
    def clone_rules(self):
        self.logger("Beginning the installation process")
        
        # Check if Wazuh manager is installed
        is_installed = False
        try:
            if self.sys_type in ['yum', 'zypper']:
                result = self.run_command("rpm -qa | grep wazuh-manager", capture_output=True)
                is_installed = bool(result.stdout.strip())
            elif self.sys_type == 'apt-get':
                result = self.run_command("apt list --installed 2>/dev/null | grep wazuh-manager", capture_output=True)
                is_installed = bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            is_installed = False
            
        if not is_installed:
            self.log_error("Wazuh-Manager software could not be found or is not installed")
            return False
            
        try:
            # Backup existing files
            self.logger("Backing up current files...")
            
            # Backup rules
            backup_dir = Path('/tmp/wazuh_rules_backup')
            backup_dir.mkdir(exist_ok=True)
            rules_files = glob.glob('/var/ossec/etc/rules/*')
            for file in rules_files:
                if os.path.isfile(file):
                    shutil.copy2(file, backup_dir)
                    
            # Backup decoders
            if os.path.exists('/var/ossec/etc/decoders'):
                backup_decoders_dir = Path('/tmp/wazuh_decoders_backup')
                backup_decoders_dir.mkdir(exist_ok=True)
                decoder_files = glob.glob('/var/ossec/etc/decoders/*')
                for file in decoder_files:
                    if os.path.isfile(file):
                        shutil.copy2(file, backup_decoders_dir)
                        
            # Backup lists
            if os.path.exists('/var/ossec/etc/lists'):
                backup_lists_dir = Path('/tmp/wazuh_lists_backup')
                backup_lists_dir.mkdir(exist_ok=True)
                list_files = glob.glob('/var/ossec/etc/lists/*')
                for file in list_files:
                    if os.path.isfile(file):
                        shutil.copy2(file, backup_lists_dir)
                    
            # Clone new rules
            if os.path.exists('/tmp/Wazuh-Rules'):
                shutil.rmtree('/tmp/Wazuh-Rules')
                
            self.run_command("git clone https://github.com/socfortress/Wazuh-Rules.git /tmp/Wazuh-Rules")
            
            # Move files from repository to appropriate directories
            if not self.move_repo_files('/tmp/Wazuh-Rules'):
                self.restore_backup()
                return False
            
            # Save version info
            with open('/tmp/version.txt', 'w') as f:
                result = self.run_command("/var/ossec/bin/wazuh-control info", capture_output=True)
                f.write(result.stdout)
                
            # Set permissions for all directories
            self.logger("Setting permissions for Wazuh files...")
            self.run_command("chown -R wazuh:wazuh /var/ossec/etc/rules/*")
            self.run_command("chmod -R 660 /var/ossec/etc/rules/*")
            
            if os.path.exists('/var/ossec/etc/decoders') and glob.glob('/var/ossec/etc/decoders/*'):
                self.run_command("chown -R wazuh:wazuh /var/ossec/etc/decoders/*")
                self.run_command("chmod -R 660 /var/ossec/etc/decoders/*")
                
            if os.path.exists('/var/ossec/etc/lists') and glob.glob('/var/ossec/etc/lists/*'):
                self.run_command("chown -R wazuh:wazuh /var/ossec/etc/lists/*")
                self.run_command("chmod -R 660 /var/ossec/etc/lists/*")
            
            # Restart service
            self.logger("Rules downloaded, attempting to restart the Wazuh-Manager service")
            if not self.restart_service("wazuh-manager"):
                self.restore_backup()
                return False
                
            return True
            
        except Exception as e:
            self.log_error(f"Failed to clone and install rules: {e}")
            self.restore_backup()
            return False
            
    def get_confirmation(self):
        """Get user confirmation unless skipped"""
        if self.skip_confirmation:
            self.logger("Confirmation skipped with -y flag")
            return True
            
        while True:
            try:
                response = input(
                    "Do you wish to configure Wazuh with the ITSEC ruleset? "
                    "WARNING - This script will replace all of your current custom Wazuh Rules. "
                    "Please proceed with caution and it is recommended to manually back up your rules... "
                    "continue? (y/n) "
                ).lower().strip()
                
                if response in ['y', 'yes']:
                    return True
                elif response in ['n', 'no']:
                    return False
                else:
                    print("Please answer yes or no.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return False
                
    def main(self):
        """Main function"""
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Check if running as root
        if os.geteuid() != 0:
            self.log_error("This script must be run as root.")
            sys.exit(1)
            
        # Determine package manager
        self.sys_type = self.detect_package_manager()
        
        # Get confirmation
        if not self.get_confirmation():
            sys.exit(0)
            
        # Run installation steps
        try:
            self.check_dependencies()
            self.check_architecture()
            
            if not self.clone_rules():
                sys.exit(1)
                
            if not self.health_check():
                sys.exit(1)
                
            self.logger("Installation process completed")
            
        except KeyboardInterrupt:
            self.log_error("Installation interrupted by user")
            sys.exit(1)
        except Exception as e:
            self.log_error(f"Installation failed: {e}")
            sys.exit(1)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Configure Wazuh with SOCFortress ruleset",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )
    
    parser.add_argument(
        '-d', '--debug',
        action='store_true', 
        help='Enable debug output'
    )
    
    return parser.parse_args()


if __name__ == "__main__":
    # Parse arguments
    args = parse_arguments()
    
    # Create configurator instance
    configurator = WazuhConfigurator()
    configurator.skip_confirmation = args.yes
    configurator.debug = args.debug
    
    # Run main function
    configurator.main()
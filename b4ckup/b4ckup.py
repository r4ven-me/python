#!/usr/bin/env python3

"""Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"""
# -*- coding: utf-8 -*-
__version__ = "0.9.5"
__status__ = "test"
__author__ = "Ivan Cherniy"
__email__ = "kar-kar@r4ven.me"
__copyright__ = "Copyright 2024, r4ven.me"
__license__ = "GPL3"

###############
### GENERAL ###
###############

# Import necessary libraries for the script
import os
import sys
import subprocess
import traceback
import time
import datetime
import shutil
import psutil
import logging
import re
import getpass
import configargparse

# Define global constants and paths
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LOCK_FILE = os.path.splitext(os.path.realpath(__file__))[0] + ".lock"
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
zbx_value = "0"

def main():

    def check_utility(utility_name):
        """Check if a required utility is installed"""

        if shutil.which(utility_name) is None:
            logging.error(f"{utility_name} is not installed or not found in PATH", exc_info=True)
            exit(1)


    def check_disk_space(output_dir):
        """Check available disk space in the output directory"""

        logging.info("Checking available disk space...")

        # Get the percentage of used disk space
        disk_usage = psutil.disk_usage(output_dir)
        disk_usage_percent = disk_usage.percent
        free_space = disk_usage.free

        for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
            if free_space < 1024:
                free_space_unit = f"{free_space:.2f} {unit}"
                break
            free_space /= 1024  # Convert to the next unit

        # If disk usage exceeds 95%, exit with a warning
        if disk_usage_percent > 95.0:
            logging.warning(
                f"More than 90% of disk space is used: {disk_usage_percent}%. Terminating..."
            )
            exit(1)
        else:
            logging.info(f"Disk usage: {disk_usage_percent}%")
            logging.info(f"Free space: {free_space_unit}")

    def check_exit_code(code, process):
        """Check return code of process result"""
        
        # If the exit code is not 0 (indicating success), raise an error
        if code != 0:
            logging.warning(f"Return code of {process} is not 0")
            logging.warning("It's also possible because the process may have used STDERR")
        

    def check_stderr(line, command):
        """Check errors in command output"""

        errors_list = [
            "tar error",
            "rsync: error",
            "pg_dump: error: connection",
            "pg_dump: unrecognized option",
            "mysqldump: unknown option",
            "mysqldump: Got error: 1044",
            "mysqldump: Got error: 1045",
            "mysqldump: Got error: 2013"
        ]

        for error in errors_list:
            if error in line.rstrip().lower():
                logging.error(f"Error during exec command: {command}")
                # raise ChildProcessError(f"Error in command: {command}")
                exit(1)


    def check_backup_size(backup_file, command):
        """Check size of result file"""

        backup_file_size = os.path.getsize(backup_file)

        # If the file size is 0 bytes, delete it and raise an error
        if backup_file_size == 0:
            logging.error(command, exc_info=True)
            os.remove(backup_file)
            raise ValueError(f"File {backup_file} is empty (0 byte) and removed")
        
        if backup_file_size < 1024:
            logging.warning(command)
            logging.warning(f"Size of {backup_file} is less than 1 KB")

        # Determining the appropriate unit of measurement
        for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
            if backup_file_size < 1024:
                return f"{backup_file_size:.2f} {unit}"
            backup_file_size /= 1024  # Convert to the next unit


    def remove_old_backup(output_dir, remove_old, keep, keep_weekly, keep_monthly):
        """Remove old backups based on age and retention policies"""

        # Define valid file extensions for backup files
        valid_extensions = (
            ".tar",
            ".sql",
            ".gz",
            ".bz",
            ".xz",
            ".tar.gpg",
            ".sql.gpg",
            ".gz.gpg",
            ".bz.gpg",
            ".xz.gpg",
        )

        logging.info(f"Backups older than {remove_old} days will be deleted")

        if keep:
            logging.info("Keeping backups with 'keep' in name")
        if keep_weekly:
            logging.info(f"Keeping {keep_weekly} weekly backups")
        if keep_monthly:
            logging.info(f"Keeping {keep_monthly} monthly backups")

        # Get current time in unix format
        now = time.time()

        # Lists to store weekly and monthly backups
        weekly_files = []
        monthly_files = []

        logging.info(f"Searching for files with extensions: {valid_extensions}...")

        # Loop through files in the output directory
        for file_name in os.listdir(output_dir):
            file_path = os.path.join(output_dir, file_name)

            # Check if the file has a valid backup extension
            if os.path.isfile(file_path) and file_name.endswith(valid_extensions):
                # Skip files marked with 'keep'
                if keep and "keep" in file_name:
                    continue
                
                # Collect weekly and monthly backups
                if keep_weekly and "weekly" in file_name:
                    weekly_files.append((file_name, os.path.getmtime(file_path)))
                elif keep_monthly and "monthly" in file_name:
                    monthly_files.append((file_name, os.path.getmtime(file_path)))
                else:
                    # Delete files older than the specified retention period
                    file_last_modified = os.path.getmtime(file_path)
                    
                    if (now - file_last_modified) > (remove_old * 86400): # one day
                        logging.info(f"Deleting file: {file_path}")
                        
                        try:
                            os.remove(file_path)
                        except OSError as e:
                            logging.error(f"Failed to remove file: {file_path}")
                            logging.error(f"Error details: {e}", exc_info=True)
                            pass

        def clean_old_copies(files_list, copies_to_keep, file_type):
            """Deletes old backups if their count exceeds
            the specified limit, keeping the most recent ones."""

            # Sort files by modification time (most recent first)
            files_list.sort(key=lambda x: x[1], reverse=True)

            # If the number of files exceeds the limit, remove the oldest ones
            if len(files_list) > copies_to_keep:
                for file_info in files_list[copies_to_keep:]:
                    file_path = os.path.join(output_dir, file_info[0])
                    logging.info(f"Deleting old {file_type} file: {file_path}")
                    
                    try:
                        # Attempt to remove the file
                        os.remove(file_path)
                    except OSError as e:
                        # Log an error if file removal fails
                        logging.error(f"Failed to remove file: {file_path}")
                        logging.error(f"Error details: {e}", exc_info=True)
                        pass

        # Remove old weekly backups if configured
        if keep_weekly:
            clean_old_copies(weekly_files, keep_weekly, "weekly")
        # Remove old monthly backups if configured
        if keep_monthly:
            clean_old_copies(monthly_files, keep_monthly, "monthly")


    def create_lock_file():
        """Check if previous backup process is running
        and create lock-file to protect against restart"""

        logging.info("Checking if a previous backup process is running...")

        # Check if the lock file already exists
        if os.path.exists(LOCK_FILE):
            while True:
                # Open the lock file and read the stored PID
                if os.path.exists(LOCK_FILE):
                    with open(LOCK_FILE, "r") as f:
                        try:
                            # Try to parse the PID from the file
                            pid = int(f.read().strip())
                            
                            if psutil.pid_exists(pid):
                                # If the process with the PID is still running, wait for it to finish
                                logging.warning(
                                    f"Backup process is already running (PID: {pid}). Waiting for it to complete..."
                                )
                                time.sleep(5) # Wait for 5 seconds before checking again
                            else:
                                # If the process is no longer active, continue with the current backup
                                logging.info(
                                    f"Inactive process found in lock file (PID: {pid}). Continuing..."
                                )
                                break
                        except ValueError:
                            # If the PID in the lock file is invalid, log a warning and continue
                            logging.warning("Invalid PID in lock file. Continuing...")
                            break
                else:
                    break

        # Create or overwrite the lock file with the current process's PID
        with open(LOCK_FILE, "w") as f:
            f.write(str(os.getpid()))
            logging.info(f"Lock file created: {LOCK_FILE}")


    def remove_lock_file():
        """Remove the lock file to allow future backup processes to run"""

        # Check if the lock file exists
        if os.path.exists(LOCK_FILE):
            try:
                os.remove(LOCK_FILE)
                logging.info(f"Lock file {LOCK_FILE} has been removed")
            except OSError as e:
                logging.error(f"Error while removing lock file: {e}", exc_info=True)


    def compress_backup(
        command, env, backup_file, compress_format, compress_level, encrypt_password):
        """Compression (and possibly encryption) of the backup file"""

        # Set default compression format to 'gzip' if not specified
        if not compress_format:
            compress_format = "gzip"
        
        # Set default compression level to '1' if not specified
        if not compress_level:
            compress_level = "1"

        # Check if the compression utility (gzip, bzip2, xz) is available
        check_utility(compress_format)

        logging.info("The backup file will be compressed")
        logging.info(
            f"Using compression format: {compress_format} with compression level: {compress_level}"
        )

        # Add appropriate file extension based on compression format
        if compress_format == "gzip":
            backup_file += ".gz"
        elif compress_format == "xz":
            backup_file += ".xz"
        elif compress_format == "bzip2":
            backup_file += ".bz"

        try:
            if encrypt_password:
                # Check if 'gpg' utility is available for encryption
                check_utility("gpg")
                logging.info("The backup file will be encrypted via GPG")
                
                # Update file extension to reflect encryption
                backup_file += ".gpg"
                
                # Create a temporary directory for GPG encryption
                gpg_tmp_dir = os.path.join(SCRIPT_DIR, ".gnupg")
                os.mkdir(gpg_tmp_dir, mode=0o700)
                
                # Path for the gpg password file
                gpg_pass_file = gpg_tmp_dir + "/passfile"
                
                # Write the password to a temporary file
                with open(gpg_pass_file, "w") as pass_file:
                    pass_file.write(encrypt_password)
                
                # Prepare GPG encryption command
                encrypt_command = [
                    "gpg",
                    "--quiet",
                    "--homedir",
                    gpg_tmp_dir,
                    "--batch",
                    "--yes",
                    "--symmetric",
                    "--passphrase-file",
                    gpg_pass_file,
                    # "--passphrase",
                    # encrypt_password,
                ]
                
                try:
                    with open(backup_file, "wb") as f_out:
                        with subprocess.Popen(
                            command,
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        ) as dump_process:
                            # Compress the backup data using the specified format and level
                            with subprocess.Popen(
                                [f"{compress_format}", f"-{compress_level}"],
                                stdin=dump_process.stdout,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                            ) as zip_process:
                                # Encrypt the compressed data using GPG
                                with subprocess.Popen(
                                    encrypt_command,
                                    stdin=zip_process.stdout,
                                    stdout=f_out,
                                    stderr=subprocess.PIPE
                                ) as encrypt_process:
                        
                                    # Close the stdout of the dump process to allow it to finish
                                    dump_process.stdout.close()
                                    
                                    # Capture dump processes output
                                    for line in dump_process.stderr:
                                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                        check_stderr(line.decode(), command)

                                    # Wait for the process to complete
                                    dump_process.communicate()

                                    check_exit_code(dump_process.returncode, f"{backup_tool} process")
                                    
                                    # Close the stdout of the zip process to allow it to finish
                                    zip_process.stdout.close()
                                    
                                    # Capture zip processes output
                                    for line in zip_process.stderr:
                                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                        check_stderr(line.decode(), command)
                                    
                                    # Capture encrypt processes output
                                    for line in encrypt_process.stderr:
                                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                        check_stderr(line.decode(), command)
                                    
                                    # Wait for the zip process
                                    zip_process.communicate()
                                    # if zip_errors:
                                    #     logging.warning(f"ZIP STDERR:\n\n{zip_errors}")
                                    check_exit_code(zip_process.returncode, "zip process")
                                    
                                    # Wait for the encrypt process
                                    encrypt_process.communicate()
                                    # if encrypt_errors:
                                    #     logging.warning(f"ENCRYPT STDERR:\n\n{encrypt_errors}")
                                    check_exit_code(encrypt_process.returncode, "gpg process")
                finally:
                    # Clean up the temporary GPG directory
                    logging.info("Cleaning temporary GPG files...")
                    shutil.rmtree(gpg_tmp_dir, ignore_errors=True)

            else:
                # No encryption; just compress and write the backup data
                with open(backup_file, "wb") as f_out:
                    # Run the dump process to collect backup data
                    with subprocess.Popen(
                        command,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    ) as dump_process:
                        # Compress the backup data and write to the backup file
                        with subprocess.Popen(
                                [f"{compress_format}", f"-{compress_level}"],
                                stdin=dump_process.stdout,
                                stdout=f_out,
                                stderr=subprocess.PIPE
                            ) as zip_process:
                                
                                # Close the stdout of the dump process to allow it to finish
                                dump_process.stdout.close()
                                
                                # Capture processes output
                                for line in dump_process.stderr:
                                    logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                    check_stderr(line.decode(), command)

                                for line in zip_process.stderr:
                                    logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                    check_stderr(line.decode(), command)
                        
                                # Wait for the process to complete
                                dump_process.communicate()

                                check_exit_code(dump_process.returncode, f"{backup_tool} process")
                    
                                # Wait for the zip process
                                zip_process.communicate()
                                check_exit_code(zip_process.returncode, "zip process")
        except Exception as e:
            # Log any errors encountered during the compression process and exit
            logging.error(f"Error during backup compression: {str(e)}", exc_info=True)
            exit(1)
        
        # Return the final backup file path (compressed and possibly encrypted)
        return backup_file


    def encrypt_backup(command, env, backup_file, encrypt_password):
        """Encryption of the backup file"""

        # Check if the 'gpg' utility is available for encryption
        check_utility("gpg")

        logging.info("The backup file will be encrypted via GPG")

        # Update backup file name to reflect GPG encryption
        backup_file += ".gpg"

        # Create a temporary directory for GPG encryption configuration
        gpg_tmp_dir = os.path.join(SCRIPT_DIR, ".gnupg")
        os.mkdir(gpg_tmp_dir, mode=0o700)

        # Path for the gpg password file
        gpg_pass_file = gpg_tmp_dir + "/passfile"
        
        # Write the password to a temporary file
        with open(gpg_pass_file, "w") as pass_file:
            pass_file.write(encrypt_password)

        # Prepare GPG encryption command
        encrypt_command = [
            "gpg",
            "--quiet",
            "--homedir",
            gpg_tmp_dir,
            "--batch",
            "--yes",
            "--symmetric",
            "--passphrase-file",
            gpg_pass_file,
            # "--passphrase",
            # encrypt_password,
        ]

        try:
            # Open the backup file to write encrypted data
            with open(backup_file, "wb") as f_out:
                # Start the dump process to get the backup data
                with subprocess.Popen(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                ) as dump_process:
                    # Start the encryption process, piping the dump output to GPG
                    with subprocess.Popen(
                        encrypt_command,
                        stdin=dump_process.stdout,
                        stdout=f_out,
                        stderr=subprocess.PIPE
                    ) as encrypt_process:
                        # Close the stdout of the dump process to allow it to finish
                        dump_process.stdout.close()
                        
                        # Capture processes output
                        for line in dump_process.stderr:
                            logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                            check_stderr(line.decode(), command)
                        
                        for line in encrypt_process.stderr:
                            logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                            check_stderr(line.decode(), command)

                        # Wait for the process to complete
                        dump_process.communicate()
                        check_exit_code(dump_process.returncode, f"{backup_tool} process")
                        
                        # Wait for the encrypt process
                        encrypt_process.communicate()
                        check_exit_code(encrypt_process.returncode, "gpg process")
        except Exception as e:
            # Log any errors that occur during the encryption process and exit
            logging.error(f"Error during backup encryption: {str(e)}", exc_info=True)
            exit(1)
        
        finally:
            # Clean up the temporary GPG directory
            logging.info("Cleaning temporary GPG files...")
            shutil.rmtree(gpg_tmp_dir, ignore_errors=True)

        # Return the final encrypted backup file path
        return backup_file

    def zabbix_sender(zbx_config, zbx_key, zbx_value, zbx_extra_params):
        """Send backup completion data to Zabbix"""

        # Check if the 'zabbix_sender' utility is available
        check_utility("zabbix_sender")

        # Prepare the command to send data to Zabbix
        command = [
            "zabbix_sender",
            "--config",
            zbx_config,
            "--key",
            zbx_key,
            "--value",
            zbx_value,
        ]

        # If extra parameters are provided, split and add them to the command
        if zbx_extra_params:
            command.extend(zbx_extra_params.split())

        logging.info(
            f"Sending backup status to Zabbix (1 = success, 0 = failure): {zbx_value}"
        )

        try:
            # Execute the command and raise an error if it fails
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            ) as zbx_process:
                for line in zbx_process.stdout:
                    logging.info(f"[ZABBIX] | {line.rstrip()}")
                    check_stderr(line, command)
                    
                for line in zbx_process.stderr:
                    logging.info(f"[ZABBIX] | {line.rstrip()}")
                    check_stderr(line, command)

                # Wait for the process to complete
                zbx_process.communicate()
        except subprocess.CalledProcessError as e:
            # Log any errors that occur during the data sending process
            logging.error(f"Error sending data to Zabbix: {str(e)}", exc_info=True)


    ####################
    ### BACKUP FILES ###
    ####################

    def main_file():
        """Main function of the file backup"""

        ## Tar
        def backup_tar(
            source_dir,
            source_file,
            output_dir,
            extra_params,
            compress,
            compress_format,
            compress_level,
            encrypt_password,
            filename,
            ssh_host,
            ssh_port,
            ssh_user,
            ssh_key,
            label_keep,
            label_weekly,
            label_monthly,
        ):
            """Backup files with tar"""

            # Check if the 'tar' utility is available
            check_utility("tar")

            # Determine the backup file name based on provided filename or default naming
            if not filename:
                dir_path = os.path.abspath(source_dir)
                dir_name = os.path.basename(dir_path)
                
                if label_keep:
                    backup_file = os.path.join(output_dir, f"{dir_name}_backup_keep_{TIMESTAMP}.tar")
                elif label_weekly:
                    backup_file = os.path.join(output_dir, f"{dir_name}_backup_weekly_{TIMESTAMP}.tar")
                elif label_monthly:
                    backup_file = os.path.join(output_dir, f"{dir_name}_backup_monthly_{TIMESTAMP}.tar")
                else:
                    backup_file = os.path.join(output_dir, f"{dir_name}_backup_{TIMESTAMP}.tar")
            else:
                backup_file = os.path.join(output_dir, f"{filename}.tar")

            # Prepare the command to create a tar archive
            command = [
                "tar",
                # "--warning=no-file-changed",
                # "--ignore-failed-read",
                "--create",
                f"--file={backup_file}",
                f"--directory={source_dir}",
                "./", # Include all files in the source directory
            ]

            # If specific files are provided, adjust the command accordingly
            if source_file:
                del command[4] # Remove the placeholder for "./"
                command.extend(source_file.split())

            # Adjust command if compression, SSH, or encryption is required
            if compress or ssh_host or encrypt_password:
                command[2] = "--file=-"

            if extra_params:
                # Split parameters and find the position to insert
                params_to_add = extra_params.split()
                position = command.index("--create") + 1
                
                for param in params_to_add:
                    command.insert(position, param)
                    position += 1  # Shift position after each inserted parameter

            # If using SSH, prepare the SSH command
            if ssh_host:
                check_utility("ssh")
                
                ssh_prefix = [
                    "ssh",
                    "-q",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    ssh_host,
                    "-p", ssh_port,
                    "-l", ssh_user,
                    "-i", ssh_key,
                ]
                
                command = ssh_prefix + command # Prepend SSH command to tar command

            # Set any custom environment variable for the backup process
            env = os.environ.copy()
            env["B4CKUP_ENV"] = "True"

            logging.info("Starting file backup with tar...")

            try:
                # Call the compression or encryption function based on user options
                if compress:
                    backup_file = compress_backup(
                        command,
                        env,
                        backup_file,
                        compress_format,
                        compress_level,
                        encrypt_password,
                    )
                else:
                    if encrypt_password:
                        # Encrypt the backup if a password is provided
                        backup_file = encrypt_backup(
                            command, env, backup_file, encrypt_password
                        )
                    else:
                        if ssh_host:
                            # Handle backup using SSH
                            with open(backup_file, "wb") as f_out:
                                with subprocess.Popen(
                                    command, env=env, stdout=f_out, stderr=subprocess.PIPE
                                ) as tar_process:
                                    for line in tar_process.stderr:
                                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                        check_stderr(line, command)

                                    # Wait for the process to complete
                                    tar_process.communicate()
                                    
                                    check_exit_code(tar_process.returncode, f"{backup_tool} process")
                        else:
                            # Run the tar command directly without SSH
                            with subprocess.Popen(
                                command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                # check=True
                            ) as tar_process:
                                for line in tar_process.stdout:
                                    logging.info(f"[{backup_tool.upper()}] | {line.rstrip()}")
                                    check_stderr(line, command)
                                
                                for line in tar_process.stderr:
                                    logging.info(f"[{backup_tool.upper()}] | {line.rstrip()}")
                                    check_stderr(line, command)

                                # Wait for the process to complete
                                tar_process.communicate()

                                check_exit_code(tar_process.returncode, f"{backup_tool} process")
                            
                backup_file_size = check_backup_size(backup_file, command)

                logging.info(f"File backup successfully created: {backup_file}")
                logging.info(f"File size: {backup_file_size}")
            except Exception as e:
                logging.error(f"Error during file backup with tar: {str(e)}", exc_info=True)
                exit(1)

        ## Rsync
        def backup_rsync(
            source_dir,
            source_file,
            output_dir,
            extra_params,
            ssh_host,
            ssh_port,
            ssh_user,
            ssh_key,
        ):
            """Backup files with rsync"""

            # Check if the 'rsync' utility is available
            check_utility("rsync")

            # Prepare the rsync command with standard options
            command = [
                "rsync",
                "--archive",
                "--links",
                "--hard-links",
                "--one-file-system",
                "--xattrs",
                "--human-readable",
                source_dir,
                output_dir,
            ]

            # If specific files are provided, adjust the command accordingly
            if source_file:
                file_list = []
                source_file_list = source_file.split()
                
                for file in source_file_list:
                    # Construct file paths based on whether using SSH
                    if ssh_host:
                        file_iter = f":{source_dir}/{file}"
                    else:
                        file_iter = f"{source_dir}/{file}"
                    
                    file_list.append(file_iter)
                
                command[7:8] = file_list # Replace the source_dir in command

            # Add extra parameters for the backup command if provided
            if extra_params:
                command.extend(extra_params.split())

            # If using SSH, prepare the SSH command
            if ssh_host:
                check_utility("ssh") # Check for SSH utility
                
                if not source_file:
                    command[7] = f":{source_dir}" # Adjust for SSH source if no specific files
                
                command.extend(
                    ["-e", f"ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_host} -p {ssh_port} -l {ssh_user} -i {ssh_key}"]
                )

            # Set any custom environment variable for the backup process
            env = os.environ.copy()
            env["B4CKUP_ENV"] = "True"

            logging.info("Starting file backup with rsync...")

            try:
                # Run the rsync command and check for errors
                with subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    # check=True
                ) as rsync_process:
                    for line in rsync_process.stdout:
                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip()}")
                        check_stderr(line, command)
                    
                    for line in rsync_process.stderr:
                        logging.info(f"[{backup_tool.upper()}] | {line.rstrip()}")
                        check_stderr(line, command)

                    # Wait for the process to complete
                    rsync_process.communicate()
                    
                    check_exit_code(rsync_process.returncode, f"{backup_tool} process")
        
                logging.info(f"File backup successfully created at: {output_dir}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Error during file backup with rsync: {str(e)}", exc_info=True)
                exit(1)

        ## Start backup
        if args.file_tool == "tar":
            if args.remove_old:
                # Remove old backups if specified
                remove_old_backup(
                    args.output_dir, args.remove_old, args.keep, args.keep_weekly, args.keep_monthly
                )

        # Check available disk space in the output directory
        check_disk_space(args.output_dir)

        create_lock_file()# Create a lock file to prevent concurrent backups

        # Handle encryption password input
        if args.file_tool == "tar":
            if args.encrypt_password:
                encrypt_password = args.encrypt_password
            elif args.encrypt_password_input:
                encrypt_password = getpass.getpass(prompt="Enter encryption password: ")
            else:
                encrypt_password = None

        try:
            # Execute the appropriate backup function based on user choice
            if args.file_tool == "tar":
                backup_tar(
                    args.source_dir,
                    args.source_file,
                    args.output_dir,
                    args.extra_params,
                    args.compress,
                    args.compress_format,
                    args.compress_level,
                    encrypt_password,
                    args.filename,
                    args.ssh_host,
                    args.ssh_port,
                    args.ssh_user,
                    args.ssh_key,
                    args.label_keep,
                    args.label_weekly,
                    args.label_monthly,
                )
            elif args.file_tool == "rsync":
                backup_rsync(
                    args.source_dir,
                    args.source_file,
                    args.output_dir,
                    args.extra_params,
                    args.ssh_host,
                    args.ssh_port,
                    args.ssh_user,
                    args.ssh_key,
                )
            
            # If Zabbix config and key are provided, set the value to success
            if args.zbx_config and args.zbx_key:
                global zbx_value
                zbx_value = "1"
        finally:
            remove_lock_file() # Ensure lock file is removed after operation


    ########################
    ### BACKUP DATABASE ####
    ########################

    def main_db():
        """Main function of the database backup"""

        ## Database
        def backup_database(
            db_host,
            db_port,
            db_name,
            db_user,
            db_password,
            output_dir,
            extra_params,
            compress,
            compress_format,
            compress_level,
            encrypt_password,
            filename,
            label_keep,
            label_weekly,
            label_monthly,
        ):
            """Backup selected database"""

            # Define database type
            if args.db_tool == "pg_dump":
                db_type = "PotstgreSQL"
            elif args.db_tool == "mysqldump":
                db_type = "MySQL"

            logging.info(f"Starting {db_type} database backup...")

            # Check if the dump utility is available
            check_utility(args.db_tool)

            # Set the backup file name based on provided filename or default naming
            if not filename:
                if label_keep:
                    backup_file = os.path.join(output_dir, f"{db_name}_backup_keep_{TIMESTAMP}.sql")
                elif label_weekly:
                    backup_file = os.path.join(output_dir, f"{db_name}_backup_weekly_{TIMESTAMP}.sql")
                elif label_monthly:
                    backup_file = os.path.join(output_dir, f"{db_name}_backup_monthly_{TIMESTAMP}.sql")
                else:
                    backup_file = os.path.join(output_dir, f"{db_name}_backup_{TIMESTAMP}.sql")
            else:
                backup_file = os.path.join(output_dir, f"{filename}.sql")

            # Prepare the command to dump a database
            if args.db_tool == "pg_dump":
                command = [
                    "pg_dump",
                    f"--host={db_host}",
                    f"--port={db_port}",
                    f"--dbname={db_name}",
                    f"--username={db_user}",
                    f"--file={backup_file}",
                ]
                
                # (REQUIRED) Set the PostgreSQL password environment variable
                env = os.environ.copy()
                env["PGPASSWORD"] = db_password
            elif args.db_tool == "mysqldump":
                # Path for the temporary MySQL config file
                mysql_config_path = SCRIPT_DIR + "/.mysql_temp.cnf"
                
                # Write the password to a temporary MySQL config file
                with open(mysql_config_path, "w") as mysql_config:
                    mysql_config.write(f"[client]\npassword={db_password}\n")
                
                # Set file permissions to read-only for the owner
                os.chmod(mysql_config_path, 0o400)

                command = [
                    "mysqldump",
                    f"--defaults-extra-file={mysql_config_path}",
                    f"--host={db_host}",
                    f"--port={db_port}",
                    f"--user={db_user}",
                    # f"--password={db_password}",
                    db_name,
                    f"--result-file={backup_file}",
                ]
                
                # Set any custom environment variable for backup
                env = os.environ.copy()
                env["B4CKUP_ENV"] = "True"

            # Add any extra parameters provided by the user
            if extra_params:
                command.extend(extra_params.split())

            try:
                # Handle compression or encryption as needed
                if compress:
                    # Remove the result file argument
                    if args.db_tool == "pg_dump":
                        del command[5]
                    elif args.db_tool == "mysqldump":
                        del command[6]
                    
                    backup_file = compress_backup(
                        command,
                        env,
                        backup_file,
                        compress_format,
                        compress_level,
                        encrypt_password,
                    )
                else:
                    if encrypt_password:
                        # Remove the file argument for encryption
                        if args.db_tool == "pg_dump":
                            del command[5]
                        elif args.db_tool == "mysqldump":
                            del command[6]
                        
                        backup_file = encrypt_backup(
                            command, env, backup_file, encrypt_password
                        )
                    else:
                        # Execute the command to perform the backup
                        with subprocess.Popen(
                            command,
                            env=env,
                            stderr=subprocess.PIPE,
                        ) as db_process:
                            for line in db_process.stderr:
                                logging.info(f"[{backup_tool.upper()}] | {line.rstrip().decode()}")
                                check_stderr(line.decode(), command)

                            # Wait for the processe to complete
                            db_process.communicate()

                            check_exit_code(db_process.returncode, f"{backup_tool} process")

                backup_file_size = check_backup_size(backup_file, command) # Check backup file size

                logging.info(f"{db_type} backup successfully created: {backup_file}")
                logging.info(f"File size: {backup_file_size}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Error during {db_type} backup: {str(e)}", exc_info=True)
                exit(1)
            finally:
                if args.db_tool == "mysqldump":
                    os.remove(mysql_config_path)

        # SSH tunneling
        def open_ssh_tunnel(
            ssh_host, ssh_port, ssh_user, ssh_key, db_host, db_port, local_forward_port
        ):
            """Open SSH tunnel using a private key"""

            check_utility("ssh")

            logging.info("Connecting to database via SSH tunnel...")

            ssh_command = [
                "ssh",
                "-q",
                "-f",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ExitOnForwardFailure=yes",
                "-L", f"{local_forward_port}:{db_host}:{db_port}",
                ssh_host,
                "-p", ssh_port,
                "-l", ssh_user,
                "-i", ssh_key,
                "sleep 10",
            ]

            try:
                tunnel = subprocess.Popen(ssh_command)
                time.sleep(5)
                logging.info(
                    f"SSH tunnel opened: local port {local_forward_port} -> {ssh_host}:{db_port}"
                )
            except Exception as e:
                logging.error(f"Error opening SSH tunnel: {e}", exc_info=True)
                exit(1)

            return ssh_command

        ## Start backup
        if args.remove_old:
            # Remove old backups if specified
            remove_old_backup(
                args.output_dir, args.remove_old, args.keep, args.keep_weekly, args.keep_monthly
            )

        # Check available disk space in the output directory
        check_disk_space(args.output_dir)

        create_lock_file()# Create a lock file to prevent concurrent backups

        # Set default database port if not provided by the user
        if not args.db_port:
            if args.db_tool == "pg_dump":
                db_port = 5432 # Default PostgreSQL port
            elif args.db_tool == "mysqldump":
                db_port = 3306 # Default MySQL port
        else:
            db_port = args.db_port

        # Get database password from user input if not provided
        if args.db_password:
            db_password = args.db_password
        elif args.db_password_input:
            db_password = getpass.getpass(prompt="Enter database password: ")

        # Get encryption password from user input if not provided
        if args.encrypt_password:
            encrypt_password = args.encrypt_password
        elif args.encrypt_password_input:
            encrypt_password = getpass.getpass(prompt="Enter encryption password: ")
        else:
            encrypt_password = None

        # Set local forward port for SSH if not provided
        if args.local_forward_port:
            local_forward_port = args.local_forward_port
        else:
            local_forward_port = db_port

        try:
            if args.ssh_host:
                # Open SSH tunnel if SSH host is provided
                ssh_tunnel = open_ssh_tunnel(
                    ssh_host=args.ssh_host,
                    ssh_port=args.ssh_port,
                    ssh_user=args.ssh_user,
                    ssh_key=args.ssh_key,
                    db_host=args.db_host,
                    db_port=db_port,
                    local_forward_port=local_forward_port
                )
                
                db_host = "127.0.0.1" # Use local address for database host
                db_port = local_forward_port # Use local forward port for database
            else:
                db_host = args.db_host # Use provided database host directly
            # Perform the database backup based on user choice
            backup_database(
                db_host,
                db_port,
                args.db_name,
                args.db_user,
                db_password,
                args.output_dir,
                args.extra_params,
                args.compress,
                args.compress_format,
                args.compress_level,
                encrypt_password,
                args.filename,
                args.label_keep,
                args.label_weekly,
                args.label_monthly,
            )
            
            # If Zabbix config and key are provided, set the value to success
            if args.zbx_config and args.zbx_key:
                global zbx_value
                zbx_value = "1"
        finally:
            remove_lock_file() # Ensure the lock file is removed after operation


    #########################
    ### ARGUMENTS PARSING ###
    #########################

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(
        dest="mode",
        required=True,
        help="select mode: 'file' for file backup, 'db' for database backup or config-gen to generate config",
    )

    # Parser for file backup mode
    file_parser = subparsers.add_parser("file")
    file_subparsers = file_parser.add_subparsers(
        dest="file_tool", required=True, help="file backup tool"
    )
    # Subparser for tar tool
    tar_parser = file_subparsers.add_parser("tar", help="for file archiving")
    # Subparser for rsync tool
    rsync_parser = file_subparsers.add_parser("rsync", help="for file syncing")

    # Parser for database backup mode
    db_parser = subparsers.add_parser("db")
    db_subparsers = db_parser.add_subparsers(
        dest="db_tool", required=True, help="database backup tool"
    )
    # Subparser for PostgreSQL
    postgresql_parser = db_subparsers.add_parser("pg_dump", help="for PostgreSQL")
    # Subparser for MySQL
    mysql_parser = db_subparsers.add_parser("mysqldump", help="for MySQL")

    # Parser for config generation
    config_gen_parser = subparsers.add_parser("config-gen")
    config_gen_subparsers = config_gen_parser.add_subparsers(
        dest="config_gen", required=True, help="config generation"
    )
    config_gen_tar_parser = config_gen_subparsers.add_parser(
        "tar",
        help="generate config for tar"
    )
    config_gen_rsync_parser = config_gen_subparsers.add_parser(
        "rsync",
        help="generate config for rsync"
    )
    config_gen_pg_dump_parser = config_gen_subparsers.add_parser(
        "pg_dump",
        help="generate config for pg_dump"
    )
    config_gen_mysqldump_parser = config_gen_subparsers.add_parser(
        "mysqldump",
        help="generate config for mysqldump"
    )

    # Add argument for config file and logging to all backup tools
    for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
        tool_parser.add_argument(
            "--config",
            metavar="FILE",
            is_config_file=True,
            help="path to YAML config file (command line arguments override config file values)",
        )
        tool_parser.add_argument(
            "--logfile",
            nargs="?",
            metavar="PATH",
            help="write the script output to log a file"
        )
        tool_parser.add_argument(
            "--logfile-append",
            action="store_true",
            help="append the script output to log a file"
        )
        tool_parser.add_argument(
            "--silent",
            action="store_true",
            help="enable quiet mode"
        )

    # Add database specific arguments for PostgreSQL and MySQL
    for tool_parser in [postgresql_parser, mysql_parser]:
        tool_parser.add_argument(
            "--db-host", required=True, metavar="HOST", help="database address"
        )
        tool_parser.add_argument(
            "--db-port", type=int, metavar="PORT", help="database port"
        )
        tool_parser.add_argument(
            "--db-name", required=True, metavar="NAME", help="database name"
        )
        tool_parser.add_argument(
            "--db-user", required=True, metavar="USER", help="database user"
        )
        # Mutually exclusive group for password handling
        password_group = tool_parser.add_mutually_exclusive_group()
        password_group.add_argument(
            "--db-password", metavar="PASSWORD", help="database password"
        )
        password_group.add_argument(
            "--db-password-input", action="store_true", help="enter password interactively"
        )

    # Add specific arguments for file backup tools
    for tool_parser in [tar_parser, rsync_parser]:
        tool_parser.add_argument(
            "--source-dir",
            required=True,
            metavar="PATH",
            help="path to directory with files to be backed up",
        )
        tool_parser.add_argument(
            "--source-file",
            metavar="NAME_or_LIST",
            help="optional (in quotes), name of specific file(s) in source directory (without ./)",
        )

    # Add common output directory and extra parameters for all backup tools
    for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
        tool_parser.add_argument(
            "--output-dir",
            required=True,
            metavar="PATH",
            help="path to backup storage directory",
        )
        tool_parser.add_argument(
            "--extra-params",
            metavar="PARAMS",
            help="extra parameters (in quotes) for pg_dump or mysqldump commands (if there is only one param starting with '--' add space at end)",
        )

    # Add common filename, old backup removal, and compression options
    for tool_parser in [tar_parser, postgresql_parser, mysql_parser]:
        # Mutually exclusive group for filename and label options
        filename_group = tool_parser.add_mutually_exclusive_group()
        filename_group.add_argument(
            "--filename", metavar="NAME", help="custom backup file name (no extension)"
        )
        filename_group.add_argument("--label-keep", action="store_true", help="add keep label in name")
        filename_group.add_argument("--label-weekly", action="store_true", help="add weekly label in name")
        filename_group.add_argument("--label-monthly", action="store_true", help="add monthly label in name")
        tool_parser.add_argument(
            "--remove-old",
            type=int,
            nargs="?",
            const=14,
            metavar="DAYS",
            help="delete old backups (default older 14 days), save all files with 'keep' in name",
        )
        tool_parser.add_argument(
            "--keep",
            action="store_true",
            help="save all backups with 'keep' in name",
        )
        tool_parser.add_argument(
            "--keep-weekly",
            type=int,
            nargs="?",
            const=1,
            metavar="AMOUNT",
            help="save (default 1) backups with 'weekly' in name",
        )
        tool_parser.add_argument(
            "--keep-monthly",
            type=int,
            nargs="?",
            const=1,
            metavar="AMOUNT",
            help="save (default 1) backups with 'monthly' in name",
        )
        tool_parser.add_argument("--compress", action="store_true", help="compress backup")
        tool_parser.add_argument(
            "--compress-format",
            choices=["gzip", "xz", "bzip2"],
            metavar="FORMAT",
            help="compression format: gzip, xz, bzip2",
        )
        tool_parser.add_argument(
            "--compress-level",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            metavar="LEVEL",
            help="compression ratio from 1 to 9",
        )
        # Mutually exclusive group for encryption options
        encryption_group = tool_parser.add_mutually_exclusive_group()
        encryption_group.add_argument(
            "--encrypt-password",
            metavar="PASSWORD",
            help="enable gpg ecnryption with password",
        )
        encryption_group.add_argument(
            "--encrypt-password-input",
            help="enable gpg ecnryption and enter password interactively",
        )

    # Add SSH parameters to all backup tools
    for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
        tool_parser.add_argument("--ssh-host", metavar="HOST", help="SSH host")
        tool_parser.add_argument("--ssh-port", metavar="PORT", help="SSH port")
        tool_parser.add_argument("--ssh-user", metavar="USER", help="SSH username")
        tool_parser.add_argument(
            "--ssh-key", metavar="PATH", help="path to SSH private key file"
        )

    # Add local forward port argument for database tools
    for tool_parser in [postgresql_parser, mysql_parser]:
        tool_parser.add_argument(
            "--local-forward-port",
            metavar="PORT",
            type=int,
            help="local port for SSH forwarding",
        )

    # Add Zabbix parameters to all backup tools
    for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
        tool_parser.add_argument(
            "--zbx-config", metavar="PATH", help="path to Zabbix agent config file"
        )
        tool_parser.add_argument(
            "--zbx-key", metavar="KEY", help="data key for sending to Zabbix"
        )
        tool_parser.add_argument(
            "--zbx-extra-params",
            metavar="PARAMS",
            help="extra parameters (in quotes) for zabbix_sender command (if there is one param, add space at end)",
        )

    # Execute the argument parser
    args = parser.parse_args()

    def get_env_value(value):
        """Get the environment variable value if the input matches the pattern"""

        env_var_pattern = re.compile(r"^\$([A-Z_][A-Z0-9_]*)$", re.IGNORECASE) # Regex pattern for environment variables
        match = env_var_pattern.match(value) # Check if the value matches the pattern
        
        if match:
            env_var = match.group(1) # Extract the variable name
            return os.getenv(env_var, value) # Return the value from the environment or the original value
        
        return value # Return the original value if no match

    # Loop through all arguments and reassign with environment variable values if applicable
    for arg, value in vars(args).items():
        if isinstance(value, str): # Check if the argument value is a string
            new_value = get_env_value(value) # Get the environment variable value
            setattr(args, arg, new_value) # Set the new value for the argument

    # Define the backup tool variable
    if args.mode == "db":
        backup_tool = args.db_tool
    elif args.mode == "file":
        backup_tool = args.file_tool

    # Validate required arguments based on the selected mode (file or db)
    if args.mode == "db":
        if not (
            args.db_host
            and args.db_name
            and args.db_user
            and (args.db_password or args.db_password_input)
        ):
            parser.error(
                "Required parameters to backup database: --db-host, --db-name, --db-user, --db-password or --db-password-input"
            )
        
        if (args.keep_weekly or args.keep_monthly) and not args.remove_old:
            parser.error("Required parameter to delete old backups: --remove-old")
        
        if (args.compress_format or args.compress_level) and not args.compress:
            parser.error("Required parameter to use compression: --compress")
        
        if (args.ssh_host or args.ssh_port or args.ssh_user or args.ssh_key) and not (
            args.ssh_host and args.ssh_port and args.ssh_user and args.ssh_key
        ):
            parser.error(
                "Required parameters to use SSH: --ssh-host, --ssh-port, --ssh-user and --ssh-key"
            )

    if args.mode == "file":
        if args.file_tool == "tar":
            if (args.keep_weekly or args.keep_monthly) and not args.remove_old:
                parser.error("Required parameter to delete old backups: --remove-old")
            
            if (args.compress_format or args.compress_level) and not args.compress:
                parser.error("Required parameter to use compression: --compress")
        
        if (args.ssh_host or args.ssh_port or args.ssh_user or args.ssh_key) and not (
            args.ssh_host and args.ssh_port and args.ssh_user and args.ssh_key
        ):
            parser.error(
                "Required parameters to use SSH: --ssh-host, --ssh-port, --ssh-user and --ssh-key"
            )

    if args.mode != "config-gen":
        # Check if both Zabbix config and key are provided or neither
        if (args.zbx_config and not args.zbx_key) or (args.zbx_key and not args.zbx_config):
            parser.error("Required parameters to send data to Zabbix: --zbx-config, --zbx-key")

        # Configure logging
        if args.logfile_append and not args.logfile:
             parser.error("Required parameter to write log: --logfile")

        if args.silent and not args.logfile:
            # Set logging level higher than CRITICAL to suppress all logging output
            logging.basicConfig(
                level=logging.CRITICAL + 1
            )
        else:
            if args.logfile:
                if args.logfile == "true":
                    # Define the log file name based on the script's file name
                    LOG_FILE = os.path.splitext(os.path.realpath(__file__))[0] + ".log"
                else:
                    LOG_FILE = args.logfile
                
                if not args.logfile_append:
                    # Check if the log file exists, and if so, clear its contents
                    if os.path.exists(LOG_FILE):
                        with open(LOG_FILE, 'w') as file:
                            pass # Clear the file by opening it in write mode
                
                if args.silent: 
                    # Set up logging to only file
                    log_handlers = [logging.FileHandler(LOG_FILE)]
                else:
                    # Set up logging to both file and console if a log file is specified
                    log_handlers = [logging.FileHandler(LOG_FILE), logging.StreamHandler()]
            else:
                # Otherwise, set up logging only to console
                log_handlers = [logging.StreamHandler()]
            
            # Configure logging with specified level, format, and handlers
            logging.basicConfig(
                level=logging.INFO,
                format="[%(asctime)s] - [%(levelname)s] - %(message)s",
                handlers=log_handlers
            )
            
            # Log startup message
            logging.info("*************************************")
            logging.info("*** STARTING BACKUP PYTHON SCRIPT ***")
            logging.info("*************************************")
            
            # Log the location of the log file if specified
            if args.logfile:
                logging.info(f"Log file: {LOG_FILE}")

    # Config generation for the selected backup tool
    tar_config = """\
#####################
### Tar arguments ###
#####################

# logfile: /path/to/file.log
# logfile-append: true
# silent: true
source-dir: /path/to/source/dir
# source-file: "file1 file2 file3 dir1 dir2"
output-dir: /path/to/output/dir
# extra-params: "--verbose"
# filename: custom_backup_file_name
# label-keep: true
# label-weekly: true
# label-monthly: true
# remove-old: 14
# keep: true
# keep-weekly: 2
# keep-monthly: 1
# compress: true
# compress-format: gzip
# compress-level: 9
# encrypt-password: "Pa$$W0rd"
# encrypt-password-input: true
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
    """

    rsync_config = """\
#######################
### Rsync arguments ###
#######################

# logfile: true
# logfile-append: true
# silent: true
source-dir: /path/to/source/dir
# source-file: "file1 file2 file3 dir1 dir2"
output-dir: /path/to/output/dir
# extra-params: "--verbose"
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
    """

    pg_dump_config = """\
#########################
### Pg_dump arguments ###
#########################

# logfile: /path/to/file.log
# logfile-append: true
# silent: true
db-host: 127.0.0.1
db-port: 5432
db-name: postgres
db-user: postgres
db-password: "$B4CKUP_DB_PASSWORD"
# db-password-input: true
output-dir: /path/to/output/dir
# extra-params: "--schema-only --verbose"
# filename: custom_backup_file_name
# label-keep: true
# label-weekly: true
# label-monthly: true
# remove-old: 30
# keep: true
# keep-weekly: 5
# keep-monthly: 2
# compress: true
# compress-format: bzip2
# compress-level: 9
# encrypt-password: Pa$$w0rD
# encrypt-password-input: true
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# local-forward-port: 7777
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
    """

    mysqldump_config = """\
###########################
### Mysqldump arguments ###
###########################

# logfile: overwrite
# silent: true
db-host: 127.0.0.1
db-port: 3306
db-name: mysql
db-user: mysql
db-password: "$B4CKUP_DB_PASSWORD"
# db-password-input: true
output-dir: /path/to/output/dir
# extra-params: "--no-data --single-transaction"
# filename: custom_backup_file_name
# label-keep: true
# label-weekly: true
# label-monthly: true
# remove-old: 60
# keep-weekly: 10
# keep-monthly: 4
# compress: true
# compress-format: xz
# compress-level: 9
# encrypt-password: "$B4CKUP_GPG_PASSWORD"
# encrypt-password-input: true
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# local-forward-port: 7777
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
    """

    # if '--config-gen' in sys.argv:
    if args.mode == "config-gen": 
        if args.config_gen == "tar":
            print(tar_config)
        elif args.config_gen == "rsync":
            print(rsync_config)
        elif args.config_gen == "pg_dump":
            print(pg_dump_config)
        elif args.config_gen == "mysqldump":
            print(mysqldump_config)
        exit(0)

    # Run script
    try:
        if args.mode == "file":
            main_file()
        elif args.mode == "db":
            main_db()
    finally:
        if args.zbx_config and args.zbx_key:
            zabbix_sender(
                args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params
            )


###################
### RUN IF MAIN ###
###################

if __name__ == "__main__":
    main()

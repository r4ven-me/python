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
import signal
import subprocess
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


def check_utility(utility_name):
    """Check if a required utility is installed"""

    if shutil.which(utility_name) is None:
        logging.error(f"{utility_name} is not installed or not found in PATH")
        exit(1)


def check_disk_space(output_dir):
    """Check available disk space in the output directory"""

    logging.info("Checking available disk space...")

    # Get the percentage of used disk space
    disk_usage = psutil.disk_usage(output_dir).percent

    # If disk usage exceeds 90%, exit with a warning
    if disk_usage > 90.0:
        logging.warning(
            f"More than 90% of disk space is used: {disk_usage}%. Terminating..."
        )
        exit(1)
    else:
        logging.info(f"Disk usage: {disk_usage}%")


def remove_old_backup(output_dir, remove_old, keep_weekly, keep_monthly):
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
            if "keep" in file_name:
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
                        logging.error(f"Error details: {e}")
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
                    logging.error(f"Error details: {e}")
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
            logging.error(f"Error while removing lock file: {e}")


def check_exit_code(code, process):
    """Check return code of process result"""
    
    # If the exit code is not 0 (indicating success), raise an error
    if code != 0:
        if args.mode == file:
            if args.file_tool == tar and process == "dump process":
                pass
        else:
            raise ValueError(f"Return code of {process} is not 0")
            # logging.warning(f"Return code of {process} is not 0")


def check_backup_size(file):
    """Check size of result file"""

    # If the file size is 0 bytes, delete it and raise an error
    if os.path.getsize(file) == 0:
        os.remove(file)
        raise ValueError(f"File {file} is empty (0 byte) and removed")


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
            logging.info("The backup file will be encrypted")
            
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
                    dump_process = subprocess.Popen(
                        command,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    # Compress the backup data using the specified format and level
                    zip_process = subprocess.Popen(
                        [f"{compress_format}", f"-{compress_level}"],
                        stdin=dump_process.stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    # Encrypt the compressed data using GPG
                    encrypt_process = subprocess.Popen(
                        encrypt_command,
                        stdin=zip_process.stdout,
                        stdout=f_out,
                        stderr=subprocess.PIPE
                    )
                    
                    # Close the stdout of the dump process to allow it to finish
                    dump_process.stdout.close()
                    
                    # Wait for the processes to complete and capture their outputs
                    dump_output, dump_errors = dump_process.communicate()
                    if dump_errors:
                        logging.warning(f"DUMP STDERR:\n\n{dump_errors}")
                    
                    check_exit_code(dump_process.returncode, "dump process")
                    
                    # Close the stdout of the zip process to allow it to finish
                    zip_process.stdout.close()
                    
                    # Wait for the zip process
                    zip_output, zip_errors = zip_process.communicate()
                    if zip_errors:
                        logging.warning(f"ZIP STDERR:\n\n{zip_errors}")
                    
                    check_exit_code(zip_process.returncode, "zip process")
                    
                    # Wait for the encrypt process
                    encrypt_output, encrypt_errors = encrypt_process.communicate()
                    if encrypt_errors:
                        logging.warning(f"ENCRYPT STDERR:\n\n{encrypt_errors}")
                    
                    check_exit_code(encrypt_process.returncode, "encrypt process")
                
                # Check if the resulting backup file is valid (non-empty)
                check_backup_size(backup_file)
            finally:
                # Clean up the temporary GPG directory
                logging.info("Cleaning temporary GPG files...")
                shutil.rmtree(gpg_tmp_dir, ignore_errors=True)

        else:
            # No encryption; just compress and write the backup data
            with open(backup_file, "wb") as f_out:
                # Run the dump process to collect backup data
                dump_process = subprocess.Popen(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Compress the backup data and write to the backup file
                zip_process = subprocess.Popen(
                    [f"{compress_format}", f"-{compress_level}"],
                    stdin=dump_process.stdout,
                    stdout=f_out,
                    stderr=subprocess.PIPE
                )
                
                # Close the stdout of the dump process to allow it to finish
                dump_process.stdout.close()
                
                # Wait for the processes to complete and capture their outputs
                dump_output, dump_errors = dump_process.communicate()
                if dump_errors:
                    logging.warning(f"DUMP STDERR:\n\n{dump_errors}")
                
                check_exit_code(dump_process.returncode, "dump process")
                
                # Wait for the zip process
                zip_output, zip_errors = zip_process.communicate()
                if zip_errors:
                    logging.warning(f"ZIP STDERR:\n\n{zip_errors}")
                
                check_exit_code(zip_process.returncode, "zip process")
            
            # Check if the resulting backup file is valid (non-empty)
            check_backup_size(backup_file)
    except Exception as e:
        # Log any errors encountered during the compression process and exit
        logging.error(f"Error during backup compression: {str(e)}")
        exit(1)
    
    # Return the final backup file path (compressed and possibly encrypted)
    return backup_file


def encrypt_backup(command, env, backup_file, encrypt_password):
    """Encryption of the backup file"""

    # Check if the 'gpg' utility is available for encryption
    check_utility("gpg")

    logging.info("The backup file will be encrypted")

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
            dump_process = subprocess.Popen(
                command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Start the encryption process, piping the dump output to GPG
            encrypt_process = subprocess.Popen(
                encrypt_command,
                stdin=dump_process.stdout,
                stdout=f_out,
                stderr=subprocess.PIPE
            )
            
            # Close the stdout of the dump process to allow it to finish
            dump_process.stdout.close()
            
            # Wait for the processes to complete and capture their outputs
            dump_output, dump_errors = dump_process.communicate()
            if dump_errors:
                logging.warning(f"DUMP STDERR:\n\n{dump_errors}")
            
            check_exit_code(dump_process.returncode, "dump_process")
            
            # Wait for the encrypt process
            encrypt_output, encrypt_errors = encrypt_process.communicate()
            if encrypt_errors:
                logging.warning(f"ENCRYPT STDERR:\n\n{encrypt_errors}")
            
            check_exit_code(encrypt_process.returncode, "encrypt process")
        
        # Verify the resulting backup file size to ensure it is valid
        check_backup_size(backup_file)
    except Exception as e:
        # Log any errors that occur during the encryption process and exit
        logging.error(f"Error during backup encryption: {str(e)}")
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
        zbx_process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        
        if zbx_process.stdout:
            logging.info(f"ZABBIX STDOUT:\n\n{zbx_process.stdout}")
        if zbx_process.stderr:
            logging.warning(f"ZABBIX STDERR:\n\n{zbx_process.stderr}")
    except subprocess.CalledProcessError as e:
        # Log any errors that occur during the data sending process
        logging.error(f"Error sending data to Zabbix: {str(e)}")


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

        # Add extra parameters for the backup command if provided
        # if extra_params:
        #     command.extend(extra_params.split())

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
                            tar_process = subprocess.Popen(
                                command, env=env, stdout=f_out, stderr=subprocess.PIPE
                            )
                            
                            # Wait for the encrypt process
                            tar_output, tar_errors = encrypt_process.communicate()
                            if tar_errors:
                                logging.warning(f"TAR STDERR:\n\n{tar_errors}")
                            
                            check_exit_code(tar_process.returncode, "tar process")
                        
                        check_backup_size(backup_file)
                    else:
                        # Run the tar command directly without SSH
                        tar_process = subprocess.run(
                            command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            # check=True
                        )
                        
                        if tar_process.stdout:
                            logging.info(f"TAR STDOUT:\n\n{tar_process.stdout}")
                        
                        if tar_process.stderr:
                            logging.warning(f"TAR STDERR:\n\n{tar_process.stderr}")
                        
                        check_backup_size(backup_file)
            logging.info(f"File backup successfully created: {backup_file}")
        except Exception as e:
            logging.error(f"Error during file backup with tar: {str(e)}")
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
            rsync_process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            
            if rsync_process.stdout:
                logging.info(f"RSYNC STDOUT:\n\n{rsync_process.stdout}")
            
            if rsync_process.stderr:
                logging.warning(f"RSYNC STDERR:\n\n{rsync_process.stderr}")
            
            check_backup_size(backup_file)
            
            logging.info(f"File backup successfully created at: {output_dir}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during file backup with rsync: {str(e)}")
            exit(1)

    ## Start backup
    if args.file_tool == "tar":
        if args.remove_old:
            # Remove old backups if specified
            remove_old_backup(
                args.output_dir, args.remove_old, args.keep_weekly, args.keep_monthly
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
                    db_process = subprocess.run(
                        command,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        check=True
                    )
                    
                    if db_process.stdout:
                            logging.info(f"{args.db_tool.upper()} STDOUT:\n\n{db_process.stdout}")
                    
                    if db_process.stderr:
                        logging.warning(f"{args.db_tool.upper()} STDERR:\n\n{db_process.stderr}")
                    
                    check_backup_size(backup_file) # Check backup file size
            logging.info(f"{db_type} backup successfully created: {backup_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during {db_type} backup: {str(e)}")
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
            logging.error(f"Error opening SSH tunnel: {e}")
            exit(1)

        return ssh_command

    ## Start backup
    if args.remove_old:
        # Remove old backups if specified
        remove_old_backup(
            args.output_dir, args.remove_old, args.keep_weekly, args.keep_monthly
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

    # ssh_tunnel = None # Initialize SSH tunnel variable

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
                local_forward_port=local_forward_port,
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
    help="select mode: 'file' for file backup or 'db' for database backup",
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

# Add argument for config file to all backup tools
for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
    tool_parser.add_argument(
        "--config",
        metavar="FILE",
        is_config_file=True,
        help="path to YAML config file (command line arguments override config file values)",
    )
    # Mutually exclusive group for logging
    logging_group = tool_parser.add_mutually_exclusive_group()
    logging_group.add_argument("--logfile", action="store_true", help="write log in file")
    logging_group.add_argument("--silent", action="store_true", help="enable quiet mode")

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
    tool_parser.add_argument(
        "--filename", metavar="NAME", help="custom backup file name (no extension)"
    )
    tool_parser.add_argument(
        "--remove-old",
        type=int,
        nargs="?",
        const=14,
        metavar="DAYS",
        help="delete old backups (default older 14 days), save all files with 'keep' in name",
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
    # Mutually exclusive group for label options
    label_group = tool_parser.add_mutually_exclusive_group()
    label_group.add_argument("--label-keep", action="store_true", help="add keep label in name")
    label_group.add_argument("--label-weekly", action="store_true", help="add weekly label in name")
    label_group.add_argument("--label-monthly", action="store_true", help="add monthly label in name")
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

# Check if both Zabbix config and key are provided or neither
if (args.zbx_config and not args.zbx_key) or (args.zbx_key and not args.zbx_config):
    parser.error("Required parameters to send data to Zabbix: --zbx-config, --zbx-key")


# Configure logging
if args.silent:
    # Set logging level higher than CRITICAL to suppress all logging output
    logging.basicConfig(
        level=logging.CRITICAL + 1
    )
else:
    if args.logfile:
        # Define the log file name based on the script's file name
        LOG_FILE = os.path.splitext(os.path.realpath(__file__))[0] + ".log"
        
        # Check if the log file exists, and if so, clear its contents
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as file:
                pass # Clear the file by opening it in write mode
        
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
    logging.info("*** STARTING BACKUP PYTHON SCRIPT ***")
    
    # Log the location of the log file if specified
    if args.logfile:
        logging.info(f"Log file: {LOG_FILE}")


###################
### RUN IF MAIN ###
###################

if __name__ == "__main__":
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

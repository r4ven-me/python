#!/usr/bin/env python3

"""Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"""
# -*- coding: utf-8 -*-
__version__ = "1.0.0"
__status__ = "beta"
__author__ = "Ivan Cherniy"
__email__ = "kar-kar@r4ven.me"
__copyright__ = "Copyright 2025, r4ven.me"
__license__ = "GPL3"

###############
### GENERAL ###
###############

# Import necessary libraries for the script
import os
import sys
import subprocess
import traceback
import logging
import time
import datetime
import hashlib
import re
import getpass
import shutil
import psutil
import configargparse


# Define global constants and paths
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SCRIPT_NAME = os.path.basename(sys.argv[0])
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_env_value(env_value):
    """Get the environment variable value if the input matches the pattern"""

    env_var_pattern = re.compile(
        r"^\$([A-Z_][A-Z0-9_]*)$", re.IGNORECASE
    )  # Regex pattern for environment variables
    match = env_var_pattern.match(env_value)  # Check if the value matches the pattern

    if match:
        env_var = match.group(1)  # Extract the variable name
        return os.getenv(
            env_var, env_value
        )  # Return the value from the environment or the original value

    return env_value  # Return the original value if no match


def check_utility(utility_name):
    """Check if a required utility is installed"""

    if shutil.which(utility_name) is None:
        logging.error(
            "%s is not installed or not found in PATH", utility_name, exc_info=True
        )
        sys.exit(1)


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
            "More than 90%% of disk space is used: %s%%. Terminating...",
            disk_usage_percent,
        )
        sys.exit(1)
    else:
        logging.info("Disk usage: %s%%", disk_usage_percent)
        logging.info("Free space: %s", free_space_unit)


def check_exit_code(code, process):
    """Check return code of process result"""

    # If the exit code is not 0 (indicating success), print warning
    if code != 0:
        logging.warning("Return code of %s is not 0", process)
        logging.warning(
            "It's also possible because the process may have used STDERR as STDOUT"
        )


def check_stderr(line, command):
    """Check errors in command output"""

    errors_list = [
        "tar error",
        "tar: error",
        "tar: cannot open",
        "tar: cannot stat",
        "tar: exiting with failure status due to previous errors",
        "rsync: error",
        "rsync: connection unexpectedly closed",
        "rsync: failed",
        "rsync: recv_generator: mkdir failed",
        "rsync error: syntax or usage error",
        "pg_dump: error: connection",
        "pg_dump: fatal",
        "pg_dump: unrecognized option",
        "pg_dump: error: aborting because of server version mismatch",
        "pg_dump: error: too many command-line arguments",
        "pg_dumpall: error: missing",
        "pg_dumpall: error: connection to server",
        "mysqldump: Got error: 1044",
        "mysqldump: Got error: 1045",
        "mysqldump: Got error: 2013",
        "mysqldump: unknown option",
        "mysqldump: Couldn't find table",
        "error: could not insert 'dm_snapshot': operation not permitted",
        "failure to communicate with kernel device-mapper driver.",
        "sudo: a password is required",
        "dd: unrecognized operand",
        "dd: failed to open",
    ]

    for error in errors_list:
        if error.lower() in line.rstrip().lower():
            logging.error("Error during exec command: %s", command)
            # raise ChildProcessError(f"Error in command: {command}")
            sys.exit(1)


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
        logging.warning("Size of %s is less than 1 KB", backup_file)

    # Determining the appropriate unit of measurement
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if backup_file_size < 1024:
            return f"{backup_file_size:.2f} {unit}"
        backup_file_size /= 1024  # Convert to the next unit


def remove_old_backup(output_dir, remove_old, keep, keep_weekly, keep_monthly):
    """Remove old backups based on age and retention policies"""

    if remove_old and BACKUP_TOOL != "rsync":
        pass
    else:
        return 0

    # Define valid file extensions for backup files
    valid_extensions = (
        ".tar",
        ".sql",
        ".gz",
        ".bz",
        ".xz",
        ".zst"
        ".tar.gpg",
        ".sql.gpg",
        ".gz.gpg",
        ".bz.gpg",
        ".xz.gpg",
        ".zst.gpg",
    )

    logging.info("Backups older than %s days will be deleted", remove_old)

    if keep:
        logging.info("Keeping backups with 'keep' in name")
    if keep_weekly:
        logging.info("Keeping %s weekly backups", keep_weekly)
    if keep_monthly:
        logging.info("Keeping %s monthly backups", keep_monthly)

    # Get current time in unix format
    now = time.time()

    # Lists to store weekly and monthly backups
    weekly_files = []
    monthly_files = []

    logging.info("Searching for files with extensions: %s...", valid_extensions)

    # Loop through files in the output directory
    for file_name in os.listdir(output_dir):
        file_path = os.path.join(output_dir, file_name)
        file_hash = f"{file_path}.sha256"

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

                if (now - file_last_modified) > (remove_old * 86400):  # one day
                    logging.info("Deleting file: %s", file_path)

                    try:
                        # Attempt to remove the hash file
                        os.remove(file_hash)
                    except FileNotFoundError:
                        pass

                    try:
                        os.remove(file_path)
                    except OSError as error_msg:
                        logging.error("Failed to remove file: %s", file_path)
                        logging.error("Error details: %s", error_msg, exc_info=True)

    def clean_old_copies(files_list, copies_to_keep, file_type):
        """Deletes old backups if their count exceeds
        the specified limit, keeping the most recent ones."""

        # Sort files by modification time (most recent first)
        files_list.sort(key=lambda x: x[1], reverse=True)

        # If the number of files exceeds the limit, remove the oldest ones
        if len(files_list) > copies_to_keep:
            for file_info in files_list[copies_to_keep:]:
                file_path = os.path.join(output_dir, file_info[0])
                logging.info("Deleting old %s file: %s", file_type, file_path)

                try:
                    # Attempt to remove the hash file
                    os.remove(file_hash)
                except FileNotFoundError:
                    pass

                try:
                    # Attempt to remove the backup file
                    os.remove(file_path)
                except OSError as error_msg:
                    # Log an error if file removal fails
                    logging.error("Failed to remove file: %s", file_path)
                    logging.error("Error details: %s", error_msg, exc_info=True)

    # Remove old weekly backups if configured
    if keep_weekly:
        clean_old_copies(weekly_files, keep_weekly, "weekly")
    # Remove old monthly backups if configured
    if keep_monthly:
        clean_old_copies(monthly_files, keep_monthly, "monthly")


def create_lock_file(backup_id):
    """Check if previous backup process is running
    and create lock-file to protect against restart"""

    logging.info("Checking if a previous backup process is running...")

    # Define the lock file name
    lock_file = os.path.join(SCRIPT_DIR, backup_id + ".lock")

    # Check if the lock file already exists
    if os.path.exists(lock_file):
        while True:
            # Open the lock file and read the stored PID
            if os.path.exists(lock_file):
                with open(lock_file, "r", encoding="utf-8") as f_lock:
                    try:
                        # Try to parse the PID from the file
                        pid = int(f_lock.read().strip())

                        if psutil.pid_exists(pid):
                            # If the process with the PID is still running, wait for it to finish
                            logging.warning(
                                "Backup process is already running (PID: %s). Waiting for it to complete...",
                                pid,
                            )
                            time.sleep(5)  # Wait for 5 seconds before checking again
                        else:
                            # If the process is no longer active, continue with the current backup
                            logging.info(
                                "Inactive process found in lock file (PID: %s). Continuing...",
                                pid,
                            )
                            break
                    except ValueError:
                        # If the PID in the lock file is invalid, log a warning and continue
                        logging.warning("Invalid PID in lock file. Continuing...")
                        break
            else:
                break

    # Create or overwrite the lock file with the current process's PID
    with open(lock_file, "w", encoding="utf-8") as f_lock:
        f_lock.write(str(os.getpid()))
        logging.info("Lock file created: %s", lock_file)

    return lock_file


def remove_lock_file(lock_file):
    """Remove the lock file to allow future backup processes to run"""

    # Check if the lock file exists
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            logging.info("Lock file %s has been removed", lock_file)
        except OSError as error_msg:
            logging.error(
                "Error while removing lock file: %s", error_msg, exc_info=True
            )


def calculate_sha256(file_path: str):
    """Calculates the SHA-256 hash of a file and saves it to a .sha256 file"""
    try:
        with open(file_path, 'rb') as f_backup:
            hash_hex = hashlib.sha256(f_backup.read()).hexdigest()

        with open(f"{file_path}.sha256", 'w', encoding="utf-8") as f_hash:
            f_hash.write(f"{hash_hex} {file_path}")

    except FileNotFoundError as error_msg:
        logging.error("Error hash calculating for %s: %s", file_path, error_msg, exc_info=True)
    except Exception as error_msg:
        logging.error("Error: %s", error_msg, exc_info=True)

    return hash_hex


def compress_backup(
    backup_id, command, env, backup_file, compress_format, compress_level, encrypt_password
):
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
        "Using compression format: %s with compression level: %s",
        compress_format,
        compress_level,
    )

    # Add appropriate file extension based on compression format
    if compress_format in ["gzip", "pigz"]:
        backup_file += ".gz"
    elif compress_format in ["bzip2", "pbzip2"]:
        backup_file += ".bz"
    elif compress_format == "xz":
        backup_file += ".xz"
    elif compress_format == "zstd":
        backup_file += ".zst"

    try:
        if encrypt_password:
            # Check if 'gpg' utility is available for encryption
            check_utility("gpg")
            # check_utility("gpg-agent")
            logging.info("The backup file will be encrypted via GPG")

            # Update file extension to reflect encryption
            backup_file += ".gpg"

            # Create a temporary directory for GPG encryption
            # gpg_tmp_dir = os.path.join(SCRIPT_DIR, f".{backup_id}_gnupg")
            gpg_tmp_dir = f"/dev/shm/.{backup_id}"
            os.mkdir(gpg_tmp_dir, mode=0o700)

            # Path for the gpg password file
            gpg_pass_file = gpg_tmp_dir + "/passfile"

            # Write the password to a temporary file
            with open(gpg_pass_file, "w", encoding="utf-8") as f_pass:
                f_pass.write(encrypt_password)

            # Prepare GPG encryption command
            encrypt_command = [
                "gpg",
                "--quiet",
                "--batch",
                "--yes",
                "--symmetric",
                "--cipher-algo", "AES256",
                "--homedir", gpg_tmp_dir,
                "--passphrase-file", gpg_pass_file,
            ]

            try:
                with open(backup_file, "wb") as f_out:
                    with subprocess.Popen(
                        command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    ) as dump_process:
                        # Compress the backup data using the specified format and level
                        with subprocess.Popen(
                            [f"{compress_format}", f"-{compress_level}"],
                            stdin=dump_process.stdout,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ) as zip_process:
                            # Encrypt the compressed data using GPG
                            with subprocess.Popen(
                                encrypt_command,
                                stdin=zip_process.stdout,
                                stdout=f_out,
                                stderr=subprocess.PIPE,
                            ) as encrypt_process:

                                # Close the stdout of the dump process to allow it to finish
                                dump_process.stdout.close()

                                # Capture dump processes output
                                for line in dump_process.stderr:
                                    logging.info(
                                        "[%s] | %s",
                                        BACKUP_TOOL.upper(),
                                        line.rstrip().decode(),
                                    )
                                    check_stderr(line.decode(), command)

                                # Wait for the process to complete
                                dump_process.communicate()

                                check_exit_code(
                                    dump_process.returncode,
                                    f"{BACKUP_TOOL} process",
                                )

                                # Close the stdout of the zip process to allow it to finish
                                zip_process.stdout.close()

                                # Capture zip processes output
                                for line in zip_process.stderr:
                                    logging.info(
                                        "[%s] | %s",
                                        BACKUP_TOOL.upper(),
                                        line.rstrip().decode(),
                                    )
                                    check_stderr(line.decode(), command)

                                # Capture encrypt processes output
                                for line in encrypt_process.stderr:
                                    logging.info(
                                        "[%s] | %s",
                                        BACKUP_TOOL.upper(),
                                        line.rstrip().decode(),
                                    )
                                    check_stderr(line.decode(), command)

                                # Wait for the zip process
                                zip_process.communicate()
                                check_exit_code(zip_process.returncode, "zip process")

                                # Wait for the encrypt process
                                encrypt_process.communicate()
                                check_exit_code(
                                    encrypt_process.returncode, "gpg process"
                                )
            finally:
                # Clean up the temporary GPG directory
                logging.info("Cleaning temporary GPG files...")
                shutil.rmtree(gpg_tmp_dir, ignore_errors=True)

        else:
            # No encryption; just compress and write the backup data
            with open(backup_file, "wb") as f_out:
                # Run the dump process to collect backup data
                with subprocess.Popen(
                    command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                ) as dump_process:
                    # Compress the backup data and write to the backup file
                    with subprocess.Popen(
                        [f"{compress_format}", f"-{compress_level}"],
                        stdin=dump_process.stdout,
                        stdout=f_out,
                        stderr=subprocess.PIPE,
                    ) as zip_process:

                        # Close the stdout of the dump process to allow it to finish
                        dump_process.stdout.close()

                        # Capture processes output
                        for line in dump_process.stderr:
                            logging.info(
                                "[%s] | %s",
                                BACKUP_TOOL.upper(),
                                line.rstrip().decode(),
                            )
                            check_stderr(line.decode(), command)

                        for line in zip_process.stderr:
                            logging.info(
                                "[%s] | %s",
                                BACKUP_TOOL.upper(),
                                line.rstrip().decode(),
                            )
                            check_stderr(line.decode(), command)

                        # Wait for the process to complete
                        dump_process.communicate()

                        check_exit_code(
                            dump_process.returncode, f"{BACKUP_TOOL} process"
                        )

                        # Wait for the zip process
                        zip_process.communicate()
                        check_exit_code(zip_process.returncode, "zip process")
    except Exception as error_msg:
        # Log any errors encountered during the compression process and exit
        logging.error(
            "Error during backup compression: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)

    # Return the final backup file path (compressed and possibly encrypted)
    return backup_file


def encrypt_backup(backup_id, command, env, backup_file, encrypt_password):
    """Encryption of the backup file"""

    # Check if the 'gpg' utility is available for encryption
    check_utility("gpg")

    logging.info("The backup file will be encrypted via GPG")

    # Update backup file name to reflect GPG encryption
    backup_file += ".gpg"

    # Create a temporary directory for GPG encryption configuration
    # gpg_tmp_dir = os.path.join(SCRIPT_DIR, f".{backup_id}_gnupg")
    gpg_tmp_dir = f"/dev/shm/.{backup_id}"
    os.mkdir(gpg_tmp_dir, mode=0o700)

    # Path for the gpg password file
    gpg_pass_file = gpg_tmp_dir + "/passfile"

    # Write the password to a temporary file
    with open(gpg_pass_file, "w", encoding="utf-8") as f_pass:
        f_pass.write(encrypt_password)

    # Prepare GPG encryption command
    encrypt_command = [
        "gpg",
        "--quiet",
        "--batch",
        "--yes",
        "--symmetric",
        "--cipher-algo", "AES256",
        "--homedir", gpg_tmp_dir,
        "--passphrase-file", gpg_pass_file,
        # "--passphrase",
        # encrypt_password,
    ]

    try:
        # Open the backup file to write encrypted data
        with open(backup_file, "wb") as f_out:
            # Start the dump process to get the backup data
            with subprocess.Popen(
                command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as dump_process:
                # Start the encryption process, piping the dump output to GPG
                with subprocess.Popen(
                    encrypt_command,
                    stdin=dump_process.stdout,
                    stdout=f_out,
                    stderr=subprocess.PIPE,
                ) as encrypt_process:
                    # Close the stdout of the dump process to allow it to finish
                    dump_process.stdout.close()

                    # Capture processes output
                    for line in dump_process.stderr:
                        logging.info(
                            "[%s] | %s",
                            BACKUP_TOOL.upper(),
                            line.rstrip().decode(),
                        )
                        check_stderr(line.decode(), command)

                    for line in encrypt_process.stderr:
                        logging.info(
                            "[%s] | %s",
                            BACKUP_TOOL.upper(),
                            line.rstrip().decode(),
                        )
                        check_stderr(line.decode(), command)

                    # Wait for the process to complete
                    dump_process.communicate()
                    check_exit_code(
                        dump_process.returncode, f"{BACKUP_TOOL} process"
                    )

                    # Wait for the encrypt process
                    encrypt_process.communicate()
                    check_exit_code(encrypt_process.returncode, "gpg process")
    except Exception as error_msg:
        # Log any errors that occur during the encryption process and exit
        logging.error(
            "Error during backup encryption: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)

    finally:
        # Clean up the temporary GPG directory
        logging.info("Cleaning temporary GPG files...")
        shutil.rmtree(gpg_tmp_dir, ignore_errors=True)

    # Return the final encrypted backup file path
    return backup_file


def forward_ssh_port(
    ssh_host,
    ssh_port,
    ssh_user,
    ssh_key,
    ssh_extra_params,
    db_host,
    db_port,
    local_forward_port,
):
    """Open SSH tunnel using a private key"""

    # Set local forward port for SSH if not provided
    # if not local_forward_port:
    #     local_forward_port = db_port

    check_utility("ssh")

    logging.info("Connecting to database via SSH tunnel...")

    ssh_command = [
        "ssh",
        "-q",
        *(ssh_extra_params.split() if ssh_extra_params else []),
        "-f",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ExitOnForwardFailure=yes",
        "-L",
        f"{local_forward_port}:{db_host}:{db_port}",
        ssh_host,
        "-p",
        ssh_port,
        "-l",
        ssh_user,
        "-i",
        ssh_key,
        "sleep 10",
    ]

    try:
        with subprocess.Popen(ssh_command):
            time.sleep(5)
            logging.info(
                "SSH tunnel opened: local port %s -> %s:%s",
                local_forward_port,
                ssh_host,
                db_port,
            )

    except Exception as error_msg:
        logging.error("Error opening SSH tunnel: %s", error_msg, exc_info=True)
        sys.exit(1)

    return ssh_command


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

    logging.info("Sending backup status to Zabbix (1 = success, 0 = failure)")
    logging.info("Zabbix key: %s", zbx_key)
    logging.info("Zabbix value: %s", zbx_value)

    try:
        # Execute the command and raise an error if it fails
        # If the command is executed but data is not sent, then repeat 3 times
        for _ in range(3):
            fail = False

            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            ) as zbx_process:
                for line in zbx_process.stdout:
                    logging.info("[ZABBIX] | %s", line.rstrip())
                    check_stderr(line, command)
                    if "processed: 0" in line:
                        fail = True

                for line in zbx_process.stderr:
                    logging.info("[ZABBIX] | %s", line.rstrip())
                    check_stderr(line, command)
                    if "processed: 0" in line:
                        fail = True

                # Wait for the process to complete
                zbx_process.communicate()

                if not fail:
                    break

                logging.warning(
                    "Unable to send data to Zabbix server with config: %s and key: %s, retrying...",
                    zbx_config,
                    zbx_key,
                )
                time.sleep(2)
                continue

    except subprocess.CalledProcessError as error_msg:
        # Log any errors that occur during the data sending process
        logging.error("Error sending data to Zabbix: %s", str(error_msg), exc_info=True)


def parse_common_args(tool_parser):
    """Parse parameters for all backup tools"""

    # Add argument for config file and logging to all backup tools
    tool_parser.add_argument(
        "--config",
        metavar="FILE",
        is_config_file=True,
        help="path to YAML config file (command line arguments override config file values)",
    )

    # Add logging parameters
    tool_parser.add_argument(
        "--logfile",
        nargs="?",
        metavar="PATH",
        help="write the script output to log a file",
    )
    tool_parser.add_argument(
        "--logfile-append",
        action="store_true",
        help="append the script output to log a file",
    )
    tool_parser.add_argument("--silent", action="store_true", help="disable stdout")

    # Add Zabbix parameters
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

    return tool_parser


def parse_hash_args(tool_parser):
    """Add common filename, old backup removal, and compression options"""

    tool_parser.add_argument(
        "--hash-file",
        action="store_true",
        help="create a file with sha-256 hash of buackup file",
    )


def parse_filename_args(tool_parser):
    """Mutually exclusive group for filename and label options"""

    filename_group = tool_parser.add_mutually_exclusive_group()
    filename_group.add_argument(
        "--filename", metavar="NAME", help="custom backup file name (no extension)"
    )
    filename_group.add_argument(
        "--label-keep", action="store_true", help="add keep label in name"
    )
    filename_group.add_argument(
        "--label-weekly", action="store_true", help="add weekly label in name"
    )
    filename_group.add_argument(
        "--label-monthly", action="store_true", help="add monthly label in name"
    )

    return tool_parser


def parse_retention_args(tool_parser):
    """Parse parameters for backup retention policy"""

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

    return tool_parser


def parse_compression_args(tool_parser):
    """Parse parameters for compression"""

    tool_parser.add_argument("--compress", action="store_true", help="compress backup")
    tool_parser.add_argument(
        "--compress-format",
        choices=["gzip", "pigz", "bzip2", "pbzip2", "xz", "zstd"],
        metavar="FORMAT",
        help="compression format: gzip, pigz, bzip2, pbzip, xz, zstd",
    )
    tool_parser.add_argument(
        "--compress-level",
        # choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        type=int,
        metavar="LEVEL",
        help="compression ratio from 1 to 9",
    )

    return tool_parser


def parse_encryption_args(tool_parser):
    """Mutually exclusive group for encryption options"""

    encryption_group = tool_parser.add_mutually_exclusive_group()
    encryption_group.add_argument(
        "--encrypt-password",
        metavar="PASSWORD",
        help="enable gpg ecnryption with password",
    )
    encryption_group.add_argument(
        "--encrypt-password-input",
        action="store_true",
        help="enable gpg ecnryption and enter password interactively",
    )

    return tool_parser


def parse_ssh_args(tool_parser):
    """Add SSH parameters to all backup tools"""

    tool_parser.add_argument("--ssh-host", metavar="HOST", help="SSH host")
    tool_parser.add_argument("--ssh-port", metavar="PORT", help="SSH port")
    tool_parser.add_argument("--ssh-user", metavar="USER", help="SSH username")
    tool_parser.add_argument(
        "--ssh-key", metavar="PATH", help="path to SSH private key file"
    )
    tool_parser.add_argument(
        "--ssh-extra-params",
        metavar="PARAMS",
        help="extra parameters (in quotes) for SSH",
    )

    if BACKUP_TOOL in ["pg_dump", "pg_dumpall", "mysqldump"]:
        # Add local forward port argument for database tools
        tool_parser.add_argument(
            "--local-forward-port",
            # required=True,
            metavar="PORT",
            type=int,
            help="local port for SSH forwarding",
        )

    return tool_parser


def setup_logging(parser, args):
    """Configure logging"""

    if args.logfile_append and not args.logfile:
        parser.error("Required parameter to write log: --logfile")

    if args.silent and not args.logfile:
        # Set logging level higher than CRITICAL to suppress all logging output
        logging.basicConfig(level=logging.CRITICAL + 1)
    else:
        if args.logfile:
            if args.logfile == "true":
                # Define the log file name based on the script's file name
                log_file = os.path.splitext(os.path.realpath(__file__))[0] + ".log"
            else:
                log_file = args.logfile

            if not args.logfile_append:
                # Check if the log file exists, and if so, clear its contents
                if os.path.exists(log_file):
                    with open(log_file, "w", encoding="utf-8") as f_log:
                        pass  # Clear the file by opening it in write mode

            if args.silent:
                # Set up logging to only file
                log_handlers = [logging.FileHandler(log_file)]
            else:
                # Set up logging to both file and console if a log file is specified
                log_handlers = [logging.FileHandler(log_file), logging.StreamHandler()]
        else:
            # Otherwise, set up logging only to console
            log_handlers = [logging.StreamHandler()]

        # Configure logging with specified level, format, and handlers
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] - [%(levelname)s] - %(message)s",
            handlers=log_handlers,
        )

        # Print the dividing line
        try:
            terminal_width = os.get_terminal_size().columns
            first_line = "*" * (terminal_width - 37)
            logging.info(first_line)
        except Exception:
            first_line = "*" * 80
            logging.info(first_line)

        # Log startup message
        logging.info("STARTING BACKUP PYTHON SCRIPT")

        # Log the location of the log file if specified
        if args.logfile:
            logging.info("Log file: %s", log_file)


def custom_check_args(parser, args):
    """Check if both Zabbix config and key are provided or neither"""

    if (args.zbx_config and not args.zbx_key) or (args.zbx_key and not args.zbx_config):
        parser.error(
            "Required parameters to send data to Zabbix: --zbx-config, --zbx-key"
        )

    if BACKUP_TOOL != "rsync":
        if (args.keep or args.keep_weekly or args.keep_monthly) and not args.remove_old:
            parser.error("Required parameter to delete old backups: --remove-old")

        if (args.compress_format or args.compress_level) and not args.compress:
            parser.error("Required parameter to use compression: --compress")

    if BACKUP_TOOL in ["pg_dump", "pg_dumpall", "mysqldump"]:
        if BACKUP_TOOL == "pg_dump" and not args.db_name:
            parser.error("Required parameters to use pg_dump: --db-name")

        if BACKUP_TOOL == "pg_dumpall":
            if args.db_name:
                parser.error("Unnecessary parameter: --db-name")

            if not args.filename:
                parser.error("Required parameter for pg_dumpall: --filename")

        if (args.ssh_host or args.ssh_port or args.ssh_user or args.ssh_key or args.local_forward_port) and not (
            args.ssh_host and args.ssh_port and args.ssh_user and args.ssh_key and args.local_forward_port
        ):
            parser.error(
                "Required parameters to use SSH: --ssh-host, --ssh-port, --ssh-user, --ssh-key and --local-forward-port"
            )
    else:
        if (args.ssh_host or args.ssh_port or args.ssh_user or args.ssh_key) and not (
            args.ssh_host and args.ssh_port and args.ssh_user and args.ssh_key
        ):
            parser.error(
                "Required parameters to use SSH: --ssh-host, --ssh-port, --ssh-user and --ssh-key"
            )


def run_command(cmd: list, file: str = None, env: str = None, pipe: bool = False):
    """External command execution"""

    if not pipe:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            # check=True
        ) as cmd_process:
            for line in cmd_process.stdout:
                logging.info("[%s] | %s}", BACKUP_TOOL.upper(), line.rstrip())
                check_stderr(line, cmd)

            for line in cmd_process.stderr:
                logging.info("[%s] | %s", BACKUP_TOOL.upper(), line.rstrip())
                check_stderr(line, cmd)

            # Wait for the process to complete
            cmd_process.communicate()

            check_exit_code(cmd_process.returncode, f"{BACKUP_TOOL} process")
    else:
        # Handle backup using SSH
        with open(file, "wb") as f_out:
            with subprocess.Popen(
                cmd, env=env, stdout=f_out, stderr=subprocess.PIPE
            ) as cmd_process:
                for line in cmd_process.stderr:
                    logging.info(
                        "[%s] | %s",
                        BACKUP_TOOL.upper(),
                        line.rstrip().decode(),
                    )
                    check_stderr(line.decode(), cmd)

                # Wait for the process to complete
                cmd_process.communicate()

                check_exit_code(
                    cmd_process.returncode, f"{BACKUP_TOOL} process"
                )


####################
### BACKUP FILES ###
####################

def backup_with_tar():
    """Backup files with tar"""

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for tar archiving"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(
        dest="BACKUP_TOOL",
        required=True,
    )
    tool_parser = subparsers.add_parser("tar", help="for file archiving")

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
    tool_parser.add_argument(
        "--output-dir",
        required=True,
        metavar="PATH",
        help="path to backup storage directory",
    )
    tool_parser.add_argument(
        "--extra-params",
        metavar="PARAMS",
        help=f"extra parameters (in quotes) for {BACKUP_TOOL} command (if there is only one param starting with '--' add space at end)",
    )

    # Execute the common argument parsers
    parse_common_args(tool_parser)
    parse_hash_args(tool_parser)
    parse_filename_args(tool_parser)
    parse_retention_args(tool_parser)
    parse_compression_args(tool_parser)
    parse_encryption_args(tool_parser)
    parse_ssh_args(tool_parser)

    args = parser.parse_args() # Execute the argument parser

    # Loop through all arguments and reassign with environment variable values if applicable
    for arg, value in vars(args).items():
        if isinstance(value, str):  # Check if the argument value is a string
            new_value = get_env_value(value)  # Get the environment variable value
            setattr(args, arg, new_value)  # Set the new value for the argument

    custom_check_args(parser, args) # Execute the custom argument checks

    setup_logging(parser, args) # Setup logging function

    # Define the backup id var
    dir_path = os.path.abspath(args.source_dir)
    dir_name = os.path.basename(dir_path)

    if not args.filename:
        if args.label_keep:
            backup_id = f"{BACKUP_TOOL}_{dir_name}_keep"
        elif args.label_weekly:
            backup_id = f"{BACKUP_TOOL}_{dir_name}_weekly"
        elif args.label_monthly:
            backup_id = f"{BACKUP_TOOL}_{dir_name}_monthly"
        else:
            backup_id = f"{BACKUP_TOOL}_{dir_name}"
    else:
        backup_id = f"{BACKUP_TOOL}_{args.filename}"

    # Handle encryption password input
    if not args.encrypt_password:
        args.encrypt_password = None

    if args.encrypt_password_input:
        args.encrypt_password = getpass.getpass(prompt="Enter encryption password: ")

    logging.info("Starting Tar backup...")

    # Check if the 'tar' utility is available
    check_utility(BACKUP_TOOL)

    # Remove old backups if specified
    remove_old_backup(
        args.output_dir, args.remove_old, args.keep, args.keep_weekly, args.keep_monthly
    )

    # Determine the backup file name based on provided filename or default naming
    if not args.filename:
        dir_abspath = os.path.abspath(args.source_dir)
        dir_basename = os.path.basename(dir_abspath)

        if args.label_keep:
            backup_file = os.path.join(
                args.output_dir, f"{dir_basename}_backup_keep_{TIMESTAMP}.tar"
            )
        elif args.label_weekly:
            backup_file = os.path.join(
                args.output_dir, f"{dir_basename}_backup_weekly_{TIMESTAMP}.tar"
            )
        elif args.label_monthly:
            backup_file = os.path.join(
                args.output_dir, f"{dir_basename}_backup_monthly_{TIMESTAMP}.tar"
            )
        else:
            backup_file = os.path.join(
                args.output_dir, f"{dir_basename}_backup_{TIMESTAMP}.tar"
            )
    else:
        backup_file = os.path.join(args.output_dir, f"{args.filename}.tar")

    # Check available disk space in the output directory
    check_disk_space(args.output_dir)

    # Create a lock file to prevent concurrent backups
    lock_file = create_lock_file(backup_id)

    zbx_value = "0" # Default zabbix value



    # Prepare the command to create a tar archive
    command = [
        "tar",
        # "--warning=no-file-changed",
        # "--ignore-failed-read",
        "--create",
        f"--file={backup_file}",
        f"--directory={args.source_dir}",
        "./",  # Include all files in the source directory
    ]

    # If specific files are provided, adjust the command accordingly
    if args.source_file:
        del command[4]  # Remove the placeholder for "./"
        command.extend(args.source_file.split())

    # Adjust command if compression, SSH, or encryption is required
    if args.compress or args.ssh_host or args.encrypt_password:
        command[2] = "--file=-"

    if args.extra_params:
        # Split parameters and find the position to insert
        params_to_add = args.extra_params.split()
        position = command.index("--create") + 1

        for param in params_to_add:
            command.insert(position, param)
            position += 1  # Shift position after each inserted parameter

    # If using SSH, prepare the SSH command
    if args.ssh_host:
        check_utility("ssh")

        ssh_prefix = [
            "ssh",
            "-q",
            *(args.ssh_extra_params.split() if args.ssh_extra_params else []),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            args.ssh_host,
            "-p",
            args.ssh_port,
            "-l",
            args.ssh_user,
            "-i",
            args.ssh_key,
        ]

        command = ssh_prefix + command  # Prepend SSH command to tar command

    # Set any custom environment variable for the backup process
    env = os.environ.copy()
    env["TAR_OPTIONS"] = ""

    logging.info("Starting file backup with tar...")

    try:
        # Call the compression or encryption function based on user options
        if args.compress:
            backup_file = compress_backup(
                backup_id,
                command,
                env,
                backup_file,
                args.compress_format,
                args.compress_level,
                args.encrypt_password,
            )
        else:
            if args.encrypt_password:
                # Encrypt the backup if a password is provided
                backup_file = args.encrypt_backup(
                    backup_id, command, env, backup_file, args.encrypt_password
                )
            else:
                if args.ssh_host:
                    # Handle backup using SSH
                    run_command(command, backup_file, env, pipe=True)
                else:
                    # Run the tar command directly without SSH
                    run_command(command, env)

        logging.info("File backup successfully created: %s", backup_file)
        
        backup_file_size = check_backup_size(backup_file, command) # Get file size
        logging.info("File size: %s", backup_file_size)

        if args.hash_file:
            backup_file_hash = calculate_sha256(backup_file) # Get file sha-256 hash
            logging.info("File SHA-256 hash: %s", backup_file_hash)
            logging.info("Hash saved to %s.sha256", backup_file)

        # If Zabbix config and key are provided, set the value to success
        if args.zbx_config and args.zbx_key:
            zbx_value = "1"
    except Exception as error_msg:
        logging.error(
            "Error during file backup with tar: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)
    finally:
        remove_lock_file(lock_file)  # Ensure lock file is removed after operation
        if args.zbx_config and args.zbx_key:
            zabbix_sender(
                args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params
            )


def backup_with_rsync():
    """Backup files with rsync"""

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(dest="BACKUP_TOOL", required=True)

    tool_parser = subparsers.add_parser("rsync", help="for file syncing")

    # Add specific arguments for file backup tools
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
    tool_parser.add_argument(
        "--output-dir",
        required=True,
        metavar="PATH",
        help="path to backup storage directory",
    )
    tool_parser.add_argument(
        "--extra-params",
        metavar="PARAMS",
        help=f"extra parameters (in quotes) for {BACKUP_TOOL} command, if there is only one param starting with '--' add space at end",
    )

    # Execute the common argument parsers
    parse_common_args(tool_parser)
    parse_ssh_args(tool_parser)

    args = parser.parse_args() # Execute the argument parser

    # Loop through all arguments and reassign with environment variable values if applicable
    for arg, value in vars(args).items():
        if isinstance(value, str):  # Check if the argument value is a string
            new_value = get_env_value(value)  # Get the environment variable value
            setattr(args, arg, new_value)  # Set the new value for the argument

    custom_check_args(parser, args) # Execute the custom argument checks

    setup_logging(parser, args) # Setup logging function


    dir_path = os.path.abspath(args.source_dir)
    dir_name = os.path.basename(dir_path)

    backup_id = f"{BACKUP_TOOL}_{dir_name}"

    logging.info("Starting Rsync backup...")

    # Check if the 'rsync' utility is available
    check_utility(BACKUP_TOOL)

    # Check available disk space in the output directory
    check_disk_space(args.output_dir)

    # Create a lock file to prevent concurrent backups
    lock_file = create_lock_file(backup_id)

    zbx_value = "0" # Default zabbix value

    # Prepare the rsync command with standard options
    command = [
        "rsync",
        "--archive",
        "--links",
        "--hard-links",
        "--xattrs",
        "--human-readable",
        args.source_dir,
        args.output_dir,
    ]

    # If specific files are provided, adjust the command accordingly
    if args.source_file:
        file_list = []
        source_file_list = args.source_file.split()

        for src_file in source_file_list:
            # Construct file paths based on whether using SSH
            if args.ssh_host:
                file_iter = f":{args.source_dir}/{src_file}"
            else:
                file_iter = f"{args.source_dir}/{src_file}"

            file_list.append(file_iter)

        command[6:7] = file_list  # Replace the source_dir in command

    # Add extra parameters for the backup command if provided
    if args.extra_params:
        command.extend(args.extra_params.split())

    # If using SSH, prepare the SSH command
    if args.ssh_host:
        check_utility("ssh")  # Check for SSH utility

        if not args.source_file:
            command[6] = f":{args.source_dir}"  # Adjust for SSH source if no specific files

        if not args.ssh_extra_params:
            args.ssh_extra_params = ""

        command.extend(
            [
                "-e",
                f"ssh -q {args.ssh_extra_params} -o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null {args.ssh_host} -p {args.ssh_port} "
                f"-l {args.ssh_user} -i {args.ssh_key}",
            ]
        )

    # Set any custom environment variable for the backup process
    env = os.environ.copy()
    env["RSYNC_PASSWORD"] = ""

    logging.info("Starting file backup with rsync...")

    try:
        # Run the rsync command
        run_command(command, env)

        logging.info("File backup successfully created at: %s", args.output_dir)

        # If Zabbix config and key are provided, set the value to success
        if args.zbx_config and args.zbx_key:
            zbx_value = "1"
    except subprocess.CalledProcessError as error_msg:
        logging.error(
            "Error during file backup with rsync: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)
    finally:
        remove_lock_file(lock_file)  # Ensure lock file is removed after operation
        if args.zbx_config and args.zbx_key:
            zabbix_sender(
                args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params
            )


########################
### BACKUP DATABASE ####
########################

def backup_with_db_dump():
    """Backup selected database"""

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for databases: pg_dump, mysqldump"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(
        dest="BACKUP_TOOL",
        required=True,
    )

    tool_parser = []

    if BACKUP_TOOL == "pg_dump":
        tool_parser = subparsers.add_parser("pg_dump", help="for PostgreSQL")
    elif BACKUP_TOOL == "pg_dumpall":
        tool_parser = subparsers.add_parser("pg_dumpall", help="for PostgreSQL cluster")
    elif BACKUP_TOOL == "mysqldump":
        tool_parser = subparsers.add_parser("mysqldump", help="for MySQL")

    # Add database specific arguments for PostgreSQL and MySQL
    tool_parser.add_argument(
        "--db-host", required=True, metavar="HOST", help="database address"
    )
    tool_parser.add_argument(
        "--db-port", required=True, type=int, metavar="PORT", help="database port"
    )
    tool_parser.add_argument(
        "--db-name", metavar="NAME", help="database name"
    )
    tool_parser.add_argument(
        "--db-user", required=True, metavar="USER", help="database user"
    )
    # Mutually exclusive group for password handling
    password_group = tool_parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument(
        "--db-password", metavar="PASSWORD", help="database password"
    )
    password_group.add_argument(
        "--db-password-input", action="store_true", help="enter password interactively"
    )

    # Add common output directory and extra parameters for all backup tools
    tool_parser.add_argument(
        "--output-dir",
        required=True,
        metavar="PATH",
        help="path to backup storage directory",
    )
    tool_parser.add_argument(
        "--extra-params",
        metavar="PARAMS",
        help=f"extra parameters (in quotes) for {BACKUP_TOOL} command (if there is only one param starting with '--' add space at end)",
    )

    # Execute the common argument parsers
    parse_common_args(tool_parser)
    parse_hash_args(tool_parser)
    parse_filename_args(tool_parser)
    parse_retention_args(tool_parser)
    parse_compression_args(tool_parser)
    parse_encryption_args(tool_parser)
    parse_ssh_args(tool_parser)

    args = parser.parse_args() # Execute the argument parser

    # Loop through all arguments and reassign with environment variable values if applicable
    for arg, value in vars(args).items():
        if isinstance(value, str):  # Check if the argument value is a string
            new_value = get_env_value(value)  # Get the environment variable value
            setattr(args, arg, new_value)  # Set the new value for the argument

    custom_check_args(parser, args) # Execute the custom argument checks

    setup_logging(parser, args) # Setup logging function

    # Define the backup id var
    if not args.filename:
        if args.label_keep:
            backup_id = f"{BACKUP_TOOL}_{args.db_name}_keep"
        elif args.label_weekly:
            backup_id = f"{BACKUP_TOOL}_{args.db_name}_weekly"
        elif args.label_monthly:
            backup_id = f"{BACKUP_TOOL}_{args.db_name}_monthly"
        else:
            backup_id = f"{BACKUP_TOOL}_{args.db_name}"
    else:
        backup_id = f"{BACKUP_TOOL}_{args.filename}"

    # Handle DB password input
    if args.db_password_input:
        args.db_password = getpass.getpass(prompt="Enter database password: ")

    # Handle encryption password input
    if not args.encrypt_password:
        args.encrypt_password = None

    if args.encrypt_password_input:
        args.encrypt_password = getpass.getpass(prompt="Enter encryption password: ")

    logging.info("Starting database backup...")

    # Remove old backups if specified
    remove_old_backup(
        args.output_dir, args.remove_old, args.keep, args.keep_weekly, args.keep_monthly
    )

    # Check if the pg_dump utility is available
    check_utility(BACKUP_TOOL)

    # Set the backup file name based on provided filename or default naming
    if not args.filename:
        if args.label_keep:
            backup_file = os.path.join(
                args.output_dir, f"{args.db_name}_backup_keep_{TIMESTAMP}.sql"
            )
        elif args.label_weekly:
            backup_file = os.path.join(
                args.output_dir, f"{args.db_name}_backup_weekly_{TIMESTAMP}.sql"
            )
        elif args.label_monthly:
            backup_file = os.path.join(
                args.output_dir, f"{args.db_name}_backup_monthly_{TIMESTAMP}.sql"
            )
        else:
            backup_file = os.path.join(args.output_dir, f"{args.db_name}_backup_{TIMESTAMP}.sql")
    else:
        backup_file = os.path.join(args.output_dir, f"{args.filename}.sql")

    # Check available disk space in the output directory
    check_disk_space(args.output_dir)

    # Create a lock file to prevent concurrent backups
    lock_file = create_lock_file(backup_id)

    zbx_value = "0" # Default zabbix value

    # Open SSH tunnel if SSH host is provided
    if args.ssh_host:
        if not args.local_forward_port:
            args.local_forward_port = args.db_port

        forward_ssh_port(
            args.ssh_host,
            args.ssh_port,
            args.ssh_user,
            args.ssh_key,
            args.ssh_extra_params,
            args.db_host,
            args.db_port,
            args.local_forward_port,
        )

        args.db_host = "127.0.0.1"
        args.db_port = args.local_forward_port

    command = []

    #==============#
    #== PG_DUMP ===#
    #==============#
    if BACKUP_TOOL in ["pg_dump", "pg_dumpall"]:
        # Prepare the command to dump a database
        command = [
            BACKUP_TOOL,
            f"--host={args.db_host}",
            f"--port={args.db_port}",
            *([f"--dbname={args.db_name}"] if args.db_name else []),
            # f"--dbname={args.db_name}",
            f"--username={args.db_user}",
            f"--file={backup_file}",
        ]

        # (REQUIRED) Set the PostgreSQL password environment variable
        env = os.environ.copy()
        env["PGPASSWORD"] = args.db_password

        # Handle compression or encryption as needed
        if args.compress or args.encrypt_password:
            # Remove the result file argument
            if BACKUP_TOOL == "pg_dump":
                del command[5]
            else:
                del command[4]

    #===============#
    #== MYSQLDUMP ==#
    #===============#
    elif BACKUP_TOOL == "mysqldump":
        # Path for the temporary MySQL config file
        # mysql_config_path = f"/dev/shm/.{backup_id}_mysql.cnf"

        # Write the password to a temporary MySQL config file
        # with open(mysql_config_path, "w", encoding="utf-8") as mysql_config:
        #     mysql_config.write(f"[client]\npassword={args.db_password}\n")

        # Set file permissions to read-only for the owner
        # os.chmod(mysql_config_path, 0o400)

        command = [
            "mysqldump",
            f"--host={args.db_host}",
            f"--port={args.db_port}",
            f"--user={args.db_user}",
            # f"--password={db_password}",
            args.db_name,
            f"--result-file={backup_file}",
            # f"--defaults-extra-file={mysql_config_path}",
        ]

        # Handle compression or encryption as needed
        if args.compress or args.encrypt:
            del command[5]

        # (REQUIRED) Set the MySQL password environment variable
        env = os.environ.copy()
        env["MYSQL_PWD"] = args.db_password

    # Add any extra parameters provided by the user
    if args.extra_params:
        command.extend(args.extra_params.split())

    try:
        # Handle compression or encryption as needed
        if args.compress:
            backup_file = compress_backup(
                backup_id,
                command,
                env,
                backup_file,
                args.compress_format,
                args.compress_level,
                args.encrypt_password,
            )
        elif args.encrypt_password:
            backup_file = encrypt_backup(
                backup_id, command, env, backup_file, args.encrypt_password
            )
        else:
            # Execute the command to perform the backup
            with subprocess.Popen(
                command,
                env=env,
                stderr=subprocess.PIPE,
            ) as db_process:
                for line in db_process.stderr:
                    logging.info(
                        "[%s] | %s", BACKUP_TOOL.upper(), line.rstrip().decode()
                    )
                    check_stderr(line.decode(), command)

                # Wait for the processe to complete
                db_process.communicate()

                check_exit_code(db_process.returncode, f"{BACKUP_TOOL} process")

        logging.info("Database backup successfully created: %s", backup_file)

        backup_file_size = check_backup_size(backup_file, command)  # Check backup file size
        logging.info("File size: %s", backup_file_size)

        if args.hash_file:
            backup_file_hash = calculate_sha256(backup_file) # Get file sha-256 hash
            logging.info("File SHA-256 hash: %s", backup_file_hash)
            logging.info("Hash saved to %s.sha256", backup_file)

        # If Zabbix config and key are provided, set the value to success
        if args.zbx_config and args.zbx_key:
            zbx_value = "1"
    except subprocess.CalledProcessError as error_msg:
    # except Exception as error_msg:
        logging.error(
            "Error during database backup: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)
    finally:
        # if os.path.exists(mysql_config_path):
            # os.remove(mysql_config_path)
        remove_lock_file(lock_file)  # Ensure lock file is removed after operation
        if args.zbx_config and args.zbx_key:
            zabbix_sender(
                args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params
            )


###################
### BACKUP LVM ####
###################

def backup_with_lvm():
    """Backup LVM partition with snapshot"""

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for LVM snapshot"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(dest="BACKUP_TOOL", required=True)
    tool_parser = subparsers.add_parser("lvm", help="for LVM snapshot")

    tool_parser.add_argument(
        "--vg-name",
        required=True,
        metavar="NAME",
        help="volume group name",
    )
    tool_parser.add_argument(
        "--lv-name",
        metavar="NAME",
        help="logical volume to backup",
    )
    tool_parser.add_argument(
        "--snap-size",
        required=True,
        metavar="SIZE",
        help="snapshot size (adjust based on expected changes)",
    )
    tool_parser.add_argument(
        "--output-dir",
        required=True,
        metavar="PATH",
        help="path to backup storage directory",
    )
    tool_parser.add_argument(
        "--extra-params",
        metavar="PARAMS",
        help=f"extra parameters (in quotes) for {BACKUP_TOOL} command (if there is only one param starting with '--' add space at end)",
    )

    # Execute the common argument parsers
    parse_common_args(tool_parser)
    parse_hash_args(tool_parser)
    parse_filename_args(tool_parser)
    parse_retention_args(tool_parser)
    parse_compression_args(tool_parser)
    parse_encryption_args(tool_parser)
    parse_ssh_args(tool_parser)

    args = parser.parse_args() # Execute the argument parser

    # Loop through all arguments and reassign with environment variable values if applicable
    for arg, value in vars(args).items():
        if isinstance(value, str):  # Check if the argument value is a string
            new_value = get_env_value(value)  # Get the environment variable value
            setattr(args, arg, new_value)  # Set the new value for the argument

    custom_check_args(parser, args) # Execute the custom argument checks

    setup_logging(parser, args) # Setup logging function

    # Define the backup id var
    if not args.filename:
        if args.label_keep:
            backup_id = f"{BACKUP_TOOL}_{args.lv_name}_keep"
        elif args.label_weekly:
            backup_id = f"{BACKUP_TOOL}_{args.lv_name}_weekly"
        elif args.label_monthly:
            backup_id = f"{BACKUP_TOOL}_{args.lv_name}_monthly"
        else:
            backup_id = f"{BACKUP_TOOL}_{args.lv_name}"
    else:
        backup_id = f"{BACKUP_TOOL}_{args.filename}"

    # Handle encryption password input
    if not args.encrypt_password:
        args.encrypt_password = None

    if args.encrypt_password_input:
        args.encrypt_password = getpass.getpass(prompt="Enter encryption password: ")

    logging.info("Starting LVM backup...")

    # Check if the 'lvcreate' and 'lvremove' utilities is available
    check_utility("lvcreate")
    check_utility("lvremove")

    # Remove old backups if specified
    remove_old_backup(
        args.output_dir, args.remove_old, args.keep, args.keep_weekly, args.keep_monthly
    )

    # Set the backup file name based on provided filename or default naming
    if not args.filename:
        if args.label_keep:
            backup_file = os.path.join(
                args.output_dir, f"{args.lv_name}_backup_keep_{TIMESTAMP}.img"
            )
        elif args.label_weekly:
            backup_file = os.path.join(
                args.output_dir, f"{args.lv_name}_backup_weekly_{TIMESTAMP}.img"
            )
        elif args.label_monthly:
            backup_file = os.path.join(
                args.output_dir, f"{args.lv_name}_backup_monthly_{TIMESTAMP}.img"
            )
        else:
            backup_file = os.path.join(args.output_dir, f"{args.lv_name}_backup_{TIMESTAMP}.img")
    else:
        backup_file = os.path.join(args.output_dir, f"{args.filename}.img")

    # Check available disk space in the output directory
    check_disk_space(args.output_dir)

    # Create a lock file to prevent concurrent backups
    lock_file = create_lock_file(backup_id)

    zbx_value = "0" # Default zabbix value

    # Prepare the command to create a LVM snapshot
    lvcreate = [
       "lvcreate",
       "--snapshot",
       "--name", f"{args.lv_name}-snap", 
       "--size", args.snap_size,
       f"/dev/{args.vg_name}/{args.lv_name}"
    ]

    # Prepare the command to remove a LVM snapshot
    lvremove = [
        "lvremove",
        "--force",
        f"/dev/{args.vg_name}/{args.lv_name}-snap"
    ]

    # Prepare the command to create a dd image
    dd_command = [
        "dd",
        f"if=/dev/{args.vg_name}/{args.lv_name}-snap",
        f"of={backup_file}",
        "conv=sync,noerror",
        "bs=64K"
    ]

    # Adjust command if compression, SSH, or encryption is required
    if args.compress or args.ssh_host or args.encrypt_password:
        del dd_command[2]  # Remove 'of' parameter

    # Add any extra parameters provided by the user
    if args.extra_params:
        dd_command.extend(args.extra_params.split())

    # If using SSH, prepare the SSH command
    if args.ssh_host:
        check_utility("ssh")

        ssh_prefix = [
            "ssh",
            "-q",
            *(args.ssh_extra_params.split() if args.ssh_extra_params else []),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            args.ssh_host,
            "-p", args.ssh_port,
            "-l", args.ssh_user,
            "-i", args.ssh_key,
            "sudo"
        ]

        lvcreate = ssh_prefix + lvcreate  # Prepend SSH command to lvcreate command
        lvremove = ssh_prefix + lvremove  # Prepend SSH command to lvremove command
        dd_command = ssh_prefix + dd_command  # Prepend SSH command to dd command

    # Set any custom environment variable for the backup process
    env = os.environ.copy()
    env["LVM_SUPPRESS_SYSLOG"] = "0"

    logging.info("Starting LVM backup...")

    try:
        # Create LVM snapshot
        run_command(lvcreate)

        # Call the compression or encryption function based on user options
        if args.compress:
            backup_file = compress_backup(
                backup_id,
                dd_command,
                env,
                backup_file,
                args.compress_format,
                args.compress_level,
                args.encrypt_password,
            )
        else:
            if args.encrypt_password:
                # Encrypt the backup if a password is provided
                backup_file = args.encrypt_backup(
                    backup_id, dd_command, env, backup_file, args.encrypt_password
                )
            else:
                if args.ssh_host:
                    # Handle backup using SSH
                    run_command(dd_command, backup_file, env, pipe=True)
                else:
                    # Run the lvm command directly without SSH
                    run_command(dd_command)

        logging.info("File backup successfully created: %s", backup_file)
        
        backup_file_size = check_backup_size(backup_file, dd_command) # Get file size
        logging.info("File size: %s", backup_file_size)

        if args.hash_file:
            backup_file_hash = calculate_sha256(backup_file) # Get file sha-256 hash
            logging.info("File SHA-256 hash: %s", backup_file_hash)
            logging.info("Hash saved to %s.sha256", backup_file)

        # If Zabbix config and key are provided, set the value to success
        if args.zbx_config and args.zbx_key:
            zbx_value = "1"
    except Exception as error_msg:
        logging.error(
            "Error during file backup with lvm: %s", str(error_msg), exc_info=True
        )
        sys.exit(1)
    finally:
        run_command(lvremove) # Remove LVM snapshot

        remove_lock_file(lock_file)  # Ensure lock file is removed after operation

        # Run zabbix_sender if set
        if args.zbx_config and args.zbx_key:
            zabbix_sender(
                args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params
            )


#########################
### CONFIG GENERATION ###
#########################

def config_gen():
    """Generate config for selected tool"""

    # Config generation for the selected backup tool
    tar_config = """\
#####################
### Tar arguments ###
#####################

# logfile: /path/to/file.log
# logfile-append: true
# silent: true
# hash-file: true
source-dir: /path/to/backup/dir
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
# ssh-extra-params: "-C -v"
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
output-dir: /path/to/backup/dir
# extra-params: "--verbose --progress"
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# ssh-extra-params: "-C -v"
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
"""

    # Config generation for the selected backup tool
    lvm_config = """\
#####################
### LVM arguments ###
#####################

# logfile: /path/to/file.log
# logfile-append: true
# silent: true
# hash-file: true
vg-name: vg-test
lv-name: lv-test
snap-size: 10G
output-dir: /path/to/backup/dir
# extra-params: "status=progress"
# filename: custom_backup_file_name
# label-keep: true
# label-weekly: true
# label-monthly: true
# remove-old: 14
# keep: true
# keep-weekly: 4
# keep-monthly: 2
# compress: true
# compress-format: zstd
# compress-level: 19
# encrypt-password: "Pa$$W0rd"
# encrypt-password-input: true
# ssh-host: example.com
# ssh-port: 22
# ssh-user: user
# ssh-key: /path/to/ssh/private/key
# ssh-extra-params: "-C -v"
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
# hash-file: true
db-host: 127.0.0.1
db-port: 5432
db-name: postgres
db-user: postgres
db-password: "$B4CKUP_DB_PASSWORD"
# db-password-input: true
output-dir: /path/to/backup/dir
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
# ssh-extra-params: "-C -v"
# local-forward-port: 7777
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
"""

    mysqldump_config = """\
###########################
### Mysqldump arguments ###
###########################

# logfile: /path/to/file.log
# logfile-append: true
# silent: true
# hash-file: true
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
# keep: true
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
# ssh-extra-params: "-C -v"
# local-forward-port: 7777
# zbx-config: /path/to/zabbix_agent.conf
# zbx-key: backup.status
# zbx-extra-params: "-vv"
"""

    # Create an argument parser for the backup script
    parser = configargparse.ArgumentParser(
        description="Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"
    )
    # Add subparsers for different modes of operation
    subparsers = parser.add_subparsers(
        dest="BACKUP_TOOL",
        required=True,
    )
    tool_parser = subparsers.add_parser("config-gen", help="for file archiving")

    tool_parser.add_argument("--tar", action="store_true", help="generate config for tar")
    tool_parser.add_argument("--rsync", action="store_true", help="generate config for rsync")
    tool_parser.add_argument("--lvm", action="store_true", help="generate config for lvm")
    tool_parser.add_argument("--pg_dump", action="store_true", help="generate config for pg_dump")
    tool_parser.add_argument("--mysqldump", action="store_true", help="generate config for mysqldump")

    args = parser.parse_args() # Execute the argument parser

    if args.tar:
        print(tar_config)
    elif args.rsync:
        print(rsync_config)
    elif args.lvm:
        print(lvm_config)
    elif args.pg_dump:
        print(pg_dump_config)
    elif args.mysqldump:
        print(mysqldump_config)


############
### MAIN ###
############

HELP_MESSAGE = f"""\
Python script for backup files (tar, rsync), disks (lvm) and databases (pg_dump, pg_dumpall, mysqldump).
For more help use: {SCRIPT_NAME} <backup_tool> --help
Example: {SCRIPT_NAME} tar --help"""

if len(sys.argv) < 2:
    print(HELP_MESSAGE)
    sys.exit(1)

BACKUP_TOOL = sys.argv[1]

def main():
    """Start backup"""

    if BACKUP_TOOL in ["-h", "--help"]:
        print(HELP_MESSAGE)
    elif BACKUP_TOOL == "config-gen":
        config_gen()
    elif BACKUP_TOOL == "tar":
        backup_with_tar()
    elif BACKUP_TOOL == "rsync":
        backup_with_rsync()
    elif BACKUP_TOOL == "lvm":
        backup_with_lvm()
    elif BACKUP_TOOL in ["pg_dump", "pg_dumpall", "mysqldump"]:
        backup_with_db_dump()
    else:
        print(HELP_MESSAGE)
        sys.exit(1)

if __name__ == "__main__":
    main()

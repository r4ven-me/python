#!/usr/bin/env python3

"""Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)"""
# -*- coding: utf-8 -*-
__version__ = "0.1.0"
__status__ = "test"
__author__ = "Ivan Cherniy"
__email__ = "kar-kar@r4ven.me"
__copyright__ = "Copyright 2024, r4ven.me"
__license__ = "GPL2"

###############
### GENERAL ###
###############

import os
import signal
import subprocess
import argparse
import datetime
import shutil
import getpass
import psutil
import time
import re
from sshtunnel import SSHTunnelForwarder

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LOCK_FILE = os.path.join(SCRIPT_DIR, "backup_lock.pid")
TIMESTAMP = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
zbx_value = "0"

def msg(msg_text):
    """Print message"""

    print("[" + datetime.datetime.now().strftime('%F %T.%f')[:-2] +"]" + " " + f"{msg_text}")

def check_utility(utility_name):
    """Check if utility is installed"""

    if shutil.which(utility_name) is None:
        msg(f"Error: {utility_name} not installed or not found in PATH.")
        exit(1)

def check_disk_space(output_dir):
    """Check free disk space"""

    msg(f"Checking free disk space...")

    disk_usage = psutil.disk_usage(output_dir).percent

    if disk_usage > 90.0:
        msg(f"More than 90% of free disk space is used: {disk_usage}")
        exit(1)
    else:
        msg(f"Used disk space: {disk_usage}%")

def remove_old_backup(output_dir, remove_old, keep_weekly, keep_monthly):
    """Clean old backups"""
    
    msg(f"Finding backups older than {remove_old}...")
    if keep_weekly:
        msg(f"Keeping {keep_weekly} weekly backups")
    if keep_monthly:
        msg(f"Keeping {keep_monthly} monthly backups")

    valid_extensions = (".tar", ".sql", ".gz", ".bz", ".xz")

    now = time.time()

    weekly_files = []
    monthly_files = []

    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        
        if os.path.isfile(file_path) and filename.endswith(valid_extensions):
            if keep_weekly or keep_monthly:
                if "weekly" in filename:
                        weekly_files.append((filename, os.path.getmtime(file_path)))
                elif "monthly" in filename:
                    monthly_files.append((filename, os.path.getmtime(file_path)))
            else:
                file_last_modified = os.path.getmtime(file_path)
                if (now - file_last_modified) > (remove_old * 86400):  # 86400 sec = one day
                    msg(f"Deleting regular file: {file_path}")
                    os.remove(file_path)

    def clean_old_copies(files_list, copies_to_keep, file_type):

        files_list.sort(key=lambda x: x[1], reverse=True)
        
        if len(files_list) > copies_to_keep:
            for file_info in files_list[copies_to_keep:]:
                file_path = os.path.join(output_dir, file_info[0])
                msg(f"Deleting old {file_type} file: {file_path}")
                os.remove(file_path)

    if keep_weekly:
        clean_old_copies(weekly_files, keep_weekly, 'weekly')
    if keep_monthly:
        clean_old_copies(monthly_files, keep_monthly, 'monthly')

def create_lock_file():
    """Check if previous backup process is running
       and create lock-file to protect against restart"""

    msg("Checking if previus backup process is running...")

    if os.path.exists(LOCK_FILE):
        while True:
            with open(LOCK_FILE, "r") as f:
                try:
                    pid = int(f.read().strip())
                    if psutil.pid_exists(pid):
                        msg(f"Backup process is already running  (PID: {pid}). Waiting for process to complete...")
                        time.sleep(5)
                    else:
                        msg(f"Inactive process was found in lock-file (PID: {pid}). Continue...")
                        break
                except ValueError:
                    msg("Invalid PID in lock-file. Continue...")
                    break

    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
        msg(f"Lock-file created: {LOCK_FILE}")

def remove_lock_file():
    """Delete lock file after process completed"""

    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)
        msg("Lock-file is deleted")

def compress_backup(command, env, backup_file, compress_format, compress_level):
    """Compress backup file"""

    if not compress_format:
        compress_format = "gzip"

    msg(f"Compression format: {compress_format}, compression level: {compress_level}")

    if compress_format == "gzip":
        backup_file += ".gz"
    elif compress_format == "xz":
        backup_file += ".xz"
    elif compress_format == "bzip2":
        backup_file += ".bz"

    try:
        with open(backup_file, 'wb') as f_out:
            gzip_process = subprocess.Popen([f"{compress_format}", f"-{compress_level}"],
                                             stdin=subprocess.PIPE, stdout=f_out)
            dump_process = subprocess.Popen(command, env=env, stdout=gzip_process.stdin)
            dump_process.communicate()
            gzip_process.communicate()
    except Exception as e:
        msg(f"Error when compress backup: {str(e)}")

    return backup_file

def zabbix_sender(zbx_config, zbx_key, zbx_value, zbx_extra_params):
    """Send backup completion data to Zabbix"""
    
    check_utility("zabbix_sender")

    command = [
        "zabbix_sender",
        "--config", 
        zbx_config,
        "--key",
        zbx_key,
        "--value",
        zbx_value
    ]

    if zbx_extra_params:
        command.extend(zbx_extra_params.split())

    msg("Sending backup status data to Zabbix (1-success, 0-failure)")

    try:
        subprocess.run(command, check=True)
        msg(f"Data about backup status has been sent to Zabbix: {zbx_value}")
    except subprocess.CalledProcessError as e:
        msg(f"Error sending data to Zabbix: {str(e)}")

####################
### BACKUP FILES ###
####################

def main_file():
    """Main function of file backup"""
    
    ## Tar
    def backup_tar(source_dir, source_file, output_dir, extra_params, compress,
                   compress_format, compress_level, filename, ssh_host, ssh_port,
                   ssh_user, ssh_key):
        """Backup files with tar"""
        
        check_utility("tar")
        
        if not filename:
            dir_path = os.path.abspath(source_dir)
            dir_name = os.path.basename(dir_path)
            backup_file = os.path.join(output_dir, f"{dir_name}_backup_{TIMESTAMP}.tar")
        else:
            backup_file = os.path.join(output_dir, f"{filename}.tar")

        if not source_file:
            source_file = "./"

        command = [
            "tar",
            "--create",
            f"--file={backup_file}",
            f"--directory={source_dir}",
            source_file
        ]

        if extra_params:
            command.extend(extra_params.split())

        if compress or ssh_host:
            command[2] = "--file=-"
        
        ssh_prefix = [
            "ssh", ssh_host,
            "-p", ssh_port,
            "-l", ssh_user,
            "-i", ssh_key
        ]

        if ssh_host:
            check_utility("ssh")
            command = ssh_prefix + command

        env = os.environ.copy()
        env["BACKUP_ENV"] = "True"

        msg("Start file backup with tar")

        try:
            if compress:
                backup_file = compress_backup(command, env, backup_file,
                                              compress_format, compress_level)
            else:
                with open(backup_file, 'w') as f_out:
                    tar_process = subprocess.Popen(command, env=env, stdout=f_out)
                    tar_process.communicate()
                # subprocess.check_call(command)
                # subprocess.run(command, check=True)
            msg(f"File backup created successfully: {backup_file}")
        except subprocess.CalledProcessError as e:
            msg(f"Error when creating file backup with tar: {str(e)}")

    ## Rsync
    def backup_rsync(source_dir, source_file, output_dir, extra_params,
                     ssh_host, ssh_port, ssh_user, ssh_key):
        """Backup files with rsync"""
        
        check_utility("rsync")

        command = [
            "rsync",
            "--archive",
            "--links",
            "--hard-links",
            "--one-file-system",
            "--xattrs",
            "--human-readable",
            source_dir,
            output_dir
        ]

        if source_file:
            file_list = []
            source_file_list = source_file.split()
            for file in source_file_list:
                if ssh_host:
                    file_iter = f":{source_dir}/{file}"
                else:
                    file_iter = f"{source_dir}/{file}"
                file_list.append(file_iter)
            command[7:8] = file_list

        if extra_params:
            command.extend(extra_params.split())

        if ssh_host:
            check_utility("ssh")
            if not source_file:
                command[7] = f":{source_dir}"
            command.extend(["-e", f"ssh {ssh_host} -p {ssh_port} -l {ssh_user} -i {ssh_key}"])

            # command[7:8] = source_dir

        env = os.environ.copy()
        env["BACKUP_ENV"] = "True"

        msg("Start file backup with rsync")

        try:
            # with open(backup_file, 'w') as f_out:
            #     tar_process = subprocess.Popen(command, env=env, stdout=f_out)
            #     tar_process.communicate()
            # subprocess.check_call(command)
            subprocess.run(command, check=True)
            msg(f"File backup created successfully at: {output_dir}")
        except subprocess.CalledProcessError as e:
            msg(f"Error when creating file backup with rsync: {str(e)}")
    
    ## Start backup
    if args.file_tool == "tar":
        if args.remove_old:
            remove_old_backup(args.output_dir, args.remove_old,
                              args.keep_weekly, args.keep_monthly)

    check_disk_space(args.output_dir)

    create_lock_file()

    try:
        if args.file_tool == "tar":
            backup_tar(args.source_dir, args.source_file, args.output_dir,
                       args.extra_params, args.compress, args.compress_format,
                       args.compress_level, args.filename, args.ssh_host,
                       args.ssh_port, args.ssh_user, args.ssh_key)
        elif args.file_tool == "rsync":
            backup_rsync(args.source_dir, args.source_file, args.output_dir,
                         args.extra_params, args.ssh_host, args.ssh_port,
                         args.ssh_user, args.ssh_key)
        if args.zbx_config and args.zbx_key:
            global zbx_value
            zbx_value = "1"
    finally:
        remove_lock_file()

########################
### BACKUP DATABASE ####
########################

def main_db():
    """Main function of file backup"""

    ## PostgreSQL
    def backup_postgresql(db_host, db_name, db_user, db_password, output_dir, extra_params,
                          compress, compress_format, compress_level, filename):
        """Backup PostgreSQL database"""

        msg("Starting PostgreSQL database backup")
        
        check_utility("pg_dump")
        
        if not filename:
            backup_file = os.path.join(output_dir, f"{db_name}_backup_{TIMESTAMP}.sql")
        else:
            backup_file = os.path.join(output_dir, f"{filename}.sql")

        command = [
            "pg_dump", 
            f"--host={db_host}", 
            f"--dbname={db_name}", 
            f"--username={db_user}", 
            f"--file={backup_file}"
        ]

        if extra_params:
            command.extend(extra_params.split())

        env = os.environ.copy()
        env["PGPASSWORD"] = db_password

        try:
            if compress:
                del command[4]
                try:
                    backup_file = compress_backup(command, env, backup_file,
                                              compress_format, compress_level)
                except Exception as e:
                    msg(f"AAAA {e}")
            else:
                # with open(backup_file, 'w') as f_out:
                #     dump_process = subprocess.Popen(command, env=env, stdout=f_out)
                #     dump_process.communicate()
                subprocess.run(command, env=env, check=True)
            msg(f"PostgreSQL backup created successfully: {backup_file}")
        except subprocess.CalledProcessError as e:
            msg(f"Error when creating backup of PostgreSQL: {str(e)}")

    ## MySQL
    def backup_mysql(db_host, db_name, db_user, db_password, output_dir, extra_params,
                     compress, compress_format, compress_level, filename):
        """Backup MySQL database"""

        msg("Starting MySQL database backup")
        
        check_utility("mysqldump")

        if not filename:
            backup_file = os.path.join(output_dir, f"{db_name}_backup_{TIMESTAMP}.sql")
        else:
            backup_file = os.path.join(output_dir, f"{filename}.sql")
        
        command = [
            "mysqldump",
            f"--host={db_host}",
            f"--user={db_user}",
            f"--password={db_password}",
            db_name,
            f"--result-file={backup_file}"
        ]

        if extra_params:
            command.extend(extra_params.split())
        
        env = os.environ.copy()
        env["BACKUP_ENV"] = "True"

        try:
            if compress:
                del command[5]
                backup_file = compress_backup(command, env, backup_file,
                                              compress_format, compress_level)
            else:
                # with open(backup_file, 'w') as f_out:
                #     dump_process = subprocess.Popen(command, stdout=f_out)
                #     dump_process.communicate()
                subprocess.run(command, env=env, check=True)
            msg(f"MySQL backup created successfully: {backup_file}")
        except subprocess.CalledProcessError as e:
            msg(f"Error when creating backup of MySQL: {str(e)}")

    # SSH tunneling
    def open_ssh_key_tunnel(ssh_host, ssh_port, ssh_user, ssh_key,
                            db_host, db_forward_port, local_forward_port):
        """Open SSH tunnel using private key"""

        msg("Connecting to database using SSH-tunnel...")

        tunnel = SSHTunnelForwarder(
            (ssh_host, int(ssh_port)),
            ssh_username=ssh_user,
            ssh_pkey=ssh_key,
            remote_bind_address=(db_host, db_forward_port),
            local_bind_address=('127.0.0.1', local_forward_port)
        )

        try:
            tunnel.start()
            msg(f"SSH-tunnel is open: {local_forward_port} -> {ssh_host}:{db_forward_port}")
        except Exception as e:
            msg(f"Error when opening SSH-tunnel: {e}")

        return tunnel

    def open_ssh_password_tunnel(ssh_host, ssh_port, ssh_user, ssh_password,
                                 db_host, db_forward_port, local_forward_port):
        """Open SSH-tunnel using password"""

        msg("Connecting to database using SSH-tunnel...")

        tunnel = SSHTunnelForwarder(
            (ssh_host, int(ssh_port)),
            ssh_username=ssh_user,
            ssh_password=ssh_password,
            remote_bind_address=(db_host, db_forward_port),
            local_bind_address=('127.0.0.1', local_forward_port)
        )

        try:
            tunnel.start()
            msg(f"SSH-tunnel is open: {local_forward_port} -> {ssh_host}:{db_forward_port}")
        except Exception as e:
            msg(f"Error when opening SSH-tunnel: {e}")

        return tunnel

    def close_ssh_tunnel(tunnel):
        """Close SSH-tunnel"""

        try:
            tunnel.stop()
            msg("SSH-tunnel is closed")
        except Exception as e:
            msg("Error when closing SSH tunnel: {e}")

    ## Start backup
    if args.remove_old:
        remove_old_backup(args.output_dir, args.remove_old,
                          args.keep_weekly, args.keep_monthly)

    check_disk_space(args.output_dir)

    create_lock_file()

    if args.db_password:
        db_password = args.db_password
    elif args.db_password_input:
        db_password = getpass.getpass(prompt="Enter database password: ")

    ssh_tunnel = None

    try:
        if args.ssh_host and args.db_forward_port:
            if args.ssh_key:
                ssh_tunnel = open_ssh_key_tunnel(
                    ssh_host=args.ssh_host,
                    ssh_port=args.ssh_port,
                    ssh_user=args.ssh_user,
                    ssh_key=args.ssh_key,
                    # ssh_password=ssh_password,
                    db_host=args.db_host,
                    db_forward_port=args.db_forward_port,
                    local_forward_port=args.local_forward_port
                )
            else:
                ssh_password = getpass.getpass(prompt="Enter SSH password: ")
                ssh_tunnel = open_ssh_password_tunnel(
                    ssh_host=args.ssh_host,
                    ssh_port=args.ssh_port,
                    ssh_user=args.ssh_user,
                    # ssh_key=args.ssh_key,
                    ssh_password=ssh_password,
                    db_host=args.db_host,
                    db_forward_port=args.db_forward_port,
                    local_forward_port=args.local_forward_port
                )
            db_host = "127.0.0.1"
        else:
            db_host = args.db_host
        if args.db_tool == "pg_dump":
            backup_postgresql(db_host, args.db_name, args.db_user, db_password,
                              args.output_dir, args.extra_params, args.compress,
                              args.compress_format, args.compress_level, args.filename)
        elif args.db_tool == "mysqldump":
            backup_mysql(db_host, args.db_name, args.db_user, db_password, args.output_dir,
                         args.extra_params, args.compress, args.compress_format,
                         args.compress_level, args.filename)
        if args.zbx_config and args.zbx_key:
            global zbx_value
            zbx_value = "1"
    finally:
        # if tunnel_server:
        #     close_ssh_tunnel(tunnel_server)
        if ssh_tunnel:
            close_ssh_tunnel(ssh_tunnel)
        remove_lock_file()

#########################
### ARGUMENTS PARSING ###
#########################

## General
parser = argparse.ArgumentParser(description="Backup script for files (tar, rsync) and databases (pg_dump, mysqldump)")
subparsers = parser.add_subparsers(dest="mode", required=True, help="Select mode: 'file' for file backup or 'db' for database backup")

## Files subparsers
file_parser = subparsers.add_parser("file")
file_subparsers = file_parser.add_subparsers(dest="file_tool", required=True, help="File backup tool")
tar_parser = file_subparsers.add_parser("tar", help="For file archiving")
rsync_parser = file_subparsers.add_parser("rsync", help="For file syncing")

## Database subparsers
db_parser = subparsers.add_parser("db")
db_subparsers = db_parser.add_subparsers(dest="db_tool", required=True, help="Database backup tool")
postgresql_parser = db_subparsers.add_parser("pg_dump", help="for PostgreSQL")
mysql_parser = db_subparsers.add_parser("mysqldump", help="for MySQL")

## Database specific args #1
for tool_parser in [postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--db-host", required=True, metavar="HOST", help="database address")
    tool_parser.add_argument("--db-name", required=True, metavar="NAME", help="database name")
    tool_parser.add_argument("--db-user", required=True, metavar="USER", help="database username")
    password_group = tool_parser.add_mutually_exclusive_group()
    password_group.add_argument("--db-password", metavar="PASSWORD", help="database password")
    password_group.add_argument("--db-password-input", action="store_true", help="enter password interactively")

## Tar and rsync specific args
for tool_parser in [tar_parser, rsync_parser]:
    tool_parser.add_argument("--source-dir", required=True, metavar="PATH", help="path to directory with files to be backed up")
    tool_parser.add_argument("--source-file", metavar="NAME_or_LIST", help="optional (in quotes), name of specific file(s) in source directory (without ./)")

## Common args #1
for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--output-dir", metavar="PATH", required=True, help="path to backup storage directory")
    tool_parser.add_argument("--extra-params", metavar="PARAMS", help="extra parameters (in quotes) for pg_dump or mysqldump commands (if there is only one param starting with '--' add space at end)")

## Tar and database specific args
for tool_parser in [tar_parser, postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--filename", metavar="NAME", help="backup file name (no extension)")
    tool_parser.add_argument("--remove-old", type=int, nargs='?', const=14, metavar="DAYS", help="delete old backups (default older 14 days)")
    tool_parser.add_argument("--keep-weekly", type=int, nargs='?', const=1, metavar="AMOUNT", help="save weekly backups (default 1)")
    tool_parser.add_argument("--keep-monthly", type=int, nargs='?', const=1, metavar="AMOUNT", help="save monthly backups (default 1)")
    tool_parser.add_argument("--compress", action="store_true", help="compress backup")
    tool_parser.add_argument("--compress-format", choices=["gzip", "xz", "bzip2"], metavar="FORMAT", help="compression format: gzip, xz, bzip2")
    tool_parser.add_argument("--compress-level", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"], metavar="LEVEL", help="compression ratio from 1 to 9", default="1")

## Common args #2
for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--ssh-host", metavar="HOST", help="SSH host for port forwarding")
    tool_parser.add_argument("--ssh-port", metavar="PORT", help="SSH port", default="22")
    tool_parser.add_argument("--ssh-user", metavar="USER", help="SSH username")
    tool_parser.add_argument("--ssh-key", metavar="PATH", help="path to SSH private key file")

## Database specific args #2
for tool_parser in [postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--local-forward-port", metavar="PORT", type=int, help="local port for SSH forwarding")
    tool_parser.add_argument("--db-forward-port", metavar="PORT", type=int, help="remote database port for SSH forwarding")

## Common args #3
for tool_parser in [tar_parser, rsync_parser, postgresql_parser, mysql_parser]:
    tool_parser.add_argument("--zbx-config", metavar="PATH", help="path to Zabbix agent config file")
    tool_parser.add_argument("--zbx-key", metavar="KEY", help="data key for sending to Zabbix")
    tool_parser.add_argument("--zbx-extra-params", metavar="PARAMS", help="extra parameters (in quotes) for zabbix_sender command (if there is one param, add space at end)")

## Parse arguments
args = parser.parse_args()

## Arguments exception
if (args.mode == "db" or args.file_tool == "tar") and ((args.ssh_host and not args.ssh_user) or (args.ssh_user and not args.ssh_host)):
    parser.error("Required parameters to use SSH: --ssh-host, --ssh-user")

if args.mode == "file" and args.file_tool != "rsync" and (args.keep_weekly or args.keep_monthly) and not args.remove_old:
    parser.error("Required parameter to delete old backups: --remove-old")

if (args.zbx_config and not args.zbx_key) or (args.zbx_key and not args.zbx_config):
    parser.error("Required parameters to send data to Zabbix: --zbx-config, --zbx-key")

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
            zabbix_sender(args.zbx_config, args.zbx_key, zbx_value, args.zbx_extra_params)

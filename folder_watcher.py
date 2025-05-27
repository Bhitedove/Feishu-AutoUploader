#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import logging
import hashlib
import configparser
import re
import shutil
import threading
from pathlib import Path
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import feishu_uploader

direct_upload = feishu_uploader.main

VERSION = "1.1.0"

DEFAULT_CONFIG = {
    'Feishu': {
        'watch_path': 'your_watch_path',
        'token_file': 'tokens.json',
        'chunk_size': '4194304',
        'debug_mode': 'false',
        'client_id': 'your_client_id',
        'client_secret': 'your_client_secret'
    },
    'Logging': {
        'enable_logging': 'true',
        'log_file': 'log/feishu_uploader.log',
        'debug_log': 'log/debug.log',
        'log_level': 'INFO',
        'state_file': 'upload_state.json'
    },
    'Rename': {
        'enabled': 'true',
        'rules': r'\[.*?\]=>; \(.*?\)=>; - (\d+)=> E\1; ^(\d+)=> E\1'
    },
    'Permissions': {
        'external_access_entity': 'open',
        'security_entity': 'anyone_can_view',
        'comment_entity': 'anyone_can_view',
        'share_entity': 'anyone',
        'link_share_entity': 'anyone_readable',
        'copy_entity': 'anyone_can_view',
        'enable_ownership_transfer': 'true',
        'enable_collaborator': 'false',
        'collaborator_id': 'your_collaborator_id',
        'new_owner_id': 'your_new_owner_id',
        'transfer_ownership': 'true',
        'need_notification': 'true',
        'remove_old_owner': 'true',
        'stay_put': 'false'
    },
    'Paths': {
        'base_url': 'https://[your-domain].feishu.cn/file/'
    }
}

def print_banner():
    print()
    print(f"\033[1;32m • 织梦字幕组飞书自动化上传工具 Feishu-AutoUploader v{VERSION}\033[0m")
    print()

def merge_default_config():
    config = configparser.ConfigParser()
    config_file = Path('config.ini') 

    if not config_file.exists():
        print('\033[33m\n • 已创建新的配置文件"config.ini"，请先修改再重新打开本程序。\033[0m\n')
        for section, options in DEFAULT_CONFIG.items():
            config.add_section(section)
            for key, value in options.items():
                config.set(section, key, value)
        
        with open('config.ini', 'w', encoding='utf-8') as configfile:
            config.write(configfile)

        if sys.platform == 'win32':
            os.system('pause')
        else:
            input("按回车键退出...") 
        sys.exit(0) 
    
    config.read('config.ini', encoding='utf-8')
    need_update = False

    for section, options in DEFAULT_CONFIG.items():
        if not config.has_section(section):
            config.add_section(section)
            need_update = True
        for key, value in options.items():
            if not config.has_option(section, key):
                config.set(section, key, value)
                need_update = True
                
    if need_update:
        print('\033[33m\n • 已更新配置文件，请补充缺失的配置项。\033[0m\n')
        with open('config.ini', 'w', encoding='utf-8') as configfile:
            config.write(configfile)

        return config
    
    for section, options in DEFAULT_CONFIG.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in options.items():
            if not config.has_option(section, key):
                config.set(section, key, value)
    with open('config.ini', 'w', encoding='utf-8') as configfile:
        config.write(configfile)
    return config

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

class UploadTracker:
    def __init__(self, state_file='upload_state.json'):
        self.state_file = state_file
        self.uploaded_files = self._load_state()
        self.lock = threading.Lock()

    def _load_state(self):
        try:
            if not os.path.exists(self.state_file):
                with open(self.state_file, 'w', encoding='utf-8') as f:
                    json.dump([], f)
                return set()
            
            with open(self.state_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return set()
                return set(json.loads(content))
        except json.JSONDecodeError:
            logging.warning("状态文件格式错误，将重置")
            return set()
        except Exception as e:
            logging.warning(f" 状态加载失败: {str(e)}")
            return set()

    def save_uploaded(self, filepath):
        with self.lock:
            try:
                file_hash = self._get_file_hash(filepath)
                self.uploaded_files.add(file_hash)
                
                temp_file = f" {self.state_file}.tmp"
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(list(self.uploaded_files), f, indent=2, ensure_ascii=False)
                
                if sys.platform == 'win32':
                    if os.path.exists(self.state_file):
                        os.unlink(self.state_file)
                    os.rename(temp_file, self.state_file)
                else:
                    os.replace(temp_file, self.state_file)
            except Exception as e:
                logging.error(f" 状态保存失败: {str(e)}")

    def is_uploaded(self, filepath):
        try:
            if not os.path.exists(filepath):
                return False
            file_hash = self._get_file_hash(filepath)
            if file_hash in self.uploaded_files:
                return True
            
            return False
        
        except PermissionError as e:
            logging.error(f" 权限拒绝访问文件: {filepath}")
            return False
        except OSError as e:
            logging.error(f" 系统级文件访问错误: {str(e)}")
            return False
        except Exception as e:
            logging.warning(f" 文件校验跳过: {str(e)}", exc_info=True)
            return False

    def _get_file_hash(self, filepath):
        file_hash = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    file_hash.update(chunk)
            return f" {file_hash.hexdigest()}_{os.path.basename(filepath)}"
        except PermissionError:
            raise PermissionError(f" 无权限读取文件: {filepath}")
        except Exception as e:
            raise RuntimeError(f" 文件读取失败: {str(e)}")

class FileHandler(FileSystemEventHandler):
    def __init__(self, config, tracker):
        super().__init__()
        self.config = config
        self.tracker = tracker
        self.logger = logging.getLogger('FileHandler')
        self.rename_enabled = config.getboolean('Rename', 'enabled', fallback=False)
        self.max_rename_attempts = 3
        self.rename_retry_delay = 5
        self.rename_rules = []
        rules_str = config.get('Rename', 'rules', fallback='')
        if rules_str.strip():
            for rule in rules_str.split(';'):
                rule = rule.strip()
                if not rule:
                    continue
                parts = rule.split('=>')
                if len(parts) == 2:
                    pattern = parts[0].strip()
                    replacement = parts[1].strip()
                    self.rename_rules.append((pattern, replacement))
                else:
                    self.logger.warning(f" 重命名规则格式错误，跳过规则: {rule}")

    def _clean_filename(self, filename):
        name, ext = os.path.splitext(filename)
        for pattern, replacement in self.rename_rules:
            try:
                name = re.sub(pattern, replacement, name)
            except re.error as e:
                self.logger.error(f" 重命名正则规则无效: pattern={pattern}, error={e}")
        return f" {name.strip()}{ext}"

    def _safe_rename(self, src, dst):
        for attempt in range(self.max_rename_attempts):
            try:
                shutil.move(src, dst)
                return True
            except (OSError, IOError):
                if attempt < self.max_rename_attempts - 1:
                    time.sleep(self.rename_retry_delay)
                else:
                    raise
        return False

    def _rename_file(self, filepath):
        if not self.rename_enabled:
            return filepath
        dirname = os.path.dirname(filepath)
        basename = os.path.basename(filepath)
        new_basename = self._clean_filename(basename)
        if new_basename != basename:
            new_path = os.path.join(dirname, new_basename)
            try:
                if self._safe_rename(filepath, new_path):
                    self.logger.info(f"文件重命名: {basename} -> {new_basename}")
                    return new_path
            except Exception as e:
                self.logger.error(f" 重命名失败: {str(e)}", exc_info=True)
        return filepath

    def on_created(self, event):
        if not event.is_directory:
            try:
                filepath = event.src_path
                filename = os.path.basename(filepath)
                if not os.access(filepath, os.R_OK):
                    self.logger.warning(f" 跳过无权限文件: {filename}")
                    return
                if not self._wait_for_file_stable(filepath):
                    self.logger.warning(f" 文件未就绪: {filename}")
                    return
                filepath = self._rename_file(filepath)
                filename = os.path.basename(filepath)
                try:
                    if self.tracker.is_uploaded(filepath):
                        self.logger.info(f"跳过已上传文件: {filename}")
                        return
                except Exception as e:
                    self.logger.warning(f" 上传状态检查跳过: {str(e)}", exc_info=True)
                self.logger.info(f"开始处理文件: {filename}")
                success, output = self._run_upload(filepath)
                self.logger.info(output) 
                if success:
                    try:
                        self.tracker.save_uploaded(filepath)
                        self.logger.info(f"上传成功: {filename}") 
                    except Exception as e:
                        print(f" [WARN] 状态保存失败: {str(e)}")
                else:
                    self.logger.error(f" 上传失败: {filename}") 
            except Exception as e:
                self.logger.error(f" 处理异常: {str(e)}", exc_info=True)
                print(f" [ERROR] 处理失败: {str(e)}")

    def _wait_for_file_stable(self, filepath, max_checks=300, delay=2):
        last_size = -1
        last_mtime = 0
        for _ in range(max_checks):
            try:
                if not os.path.exists(filepath):
                    time.sleep(delay)
                    continue
                current_size = os.path.getsize(filepath)
                current_mtime = os.path.getmtime(filepath)
                if current_size == last_size and current_mtime == last_mtime and current_size > 0:
                    return True
                last_size = current_size
                last_mtime = current_mtime
                time.sleep(delay)
            except Exception:
                time.sleep(delay)
        return False

    def _run_upload(self, filepath):
        try:
            success = direct_upload(filepath)
            return (success, "上传命令执行成功")
        except Exception as e:
            logging.exception("上传命令执行失败", exc_info=True)
            return (False, f" 上传命令执行失败: {str(e)}")

def setup_logging(config):
    def ensure_path(full_path):
        log_dir = os.path.dirname(full_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        return full_path

    main_log = ensure_path(config.get('Logging', 'log_file', fallback='log/feishu_uploader.log'))
    debug_log = ensure_path(config.get('Logging', 'debug_log', fallback='log/debug.log'))

    log_level = getattr(logging, config.get('Logging', 'log_level', fallback='INFO').upper(), logging.INFO)

    debug_handler = logging.handlers.RotatingFileHandler(
        debug_log,
        maxBytes=10*1024*1024,
        backupCount=3,
        encoding='utf-8'
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter('%(asctime)s - [DEBUG] - %(message)s'))
    logging.getLogger('FeishuDebug').addHandler(debug_handler)

    main_handler = logging.handlers.RotatingFileHandler(
        main_log,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    main_handler.setFormatter(logging.Formatter(' [%(levelname)s] %(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(' [%(levelname)s] %(message)s'))

    logger = logging.getLogger()
    logger.setLevel(log_level)
    if logger.handlers:
        return
    logger.addHandler(main_handler)
    logger.addHandler(console_handler)
    logger.info(f"日志系统初始化完成 - 主日志: {main_log}, 调试日志: {debug_log}")


def manual_upload_prompt(tracker):
    logger = logging.getLogger('ManualUpload') 
    print(" \n [手动模式] 请输入文件路径，支持直接拖入文件后回车。输入空行退出。")
    while True:
        try:
            filepath = input(" 文件路径 > ").strip().strip('"').strip("'")
            if not filepath:
                print(" 退出手动上传模式。")
                break
            if not os.path.isfile(filepath):
                logger.error(f" 文件不存在: {filepath}") 
                continue
            filename = os.path.basename(filepath)
            if tracker.is_uploaded(filepath):
                logger.info(f"文件已上传，跳过: {filename}") 
                continue
            logger.info(f"准备上传: {filename}") 
            success = direct_upload(filepath)
            if success:
                tracker.save_uploaded(filepath)
                logger.info(f"上传成功: {filename}") 
            else:
                logger.error(f" 上传失败: {filename}") 
        except KeyboardInterrupt:
            print(" \n用户终止手动上传模式。")
            break
        except Exception as e:
            logger.error(f" 手动上传异常: {str(e)}") 

def main():
    if getattr(sys, 'frozen', False):
        os.chdir(os.path.dirname(sys.executable))
    else:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs('log', exist_ok=True)

    try:
        config = merge_default_config()
    except Exception as e:
        print(f" 配置文件初始化失败: {str(e)}")
        sys.exit(1)

    print_banner()
    setup_logging(config)
    watch_path = config.get('Feishu', 'watch_path', fallback='.')
    state_file = config.get('Logging', 'state_file', fallback='upload_state.json')
    tracker = UploadTracker(state_file)

    if len(sys.argv) > 1:
        logger = logging.getLogger('CLI')
        for filepath in sys.argv[1:]:
            logger.info(f"启动检测到文件参数: {filepath}，尝试上传...")
            if not os.path.isfile(filepath):
                logger.error(f" 文件不存在或不是文件: {filepath}")
                continue
            if tracker.is_uploaded(filepath):
                logger.info(f"文件已上传，跳过: {os.path.basename(filepath)}")
                continue
            try:
                success = direct_upload(filepath)
                if success:
                    tracker.save_uploaded(filepath)
                    logger.info(f"启动上传成功: {os.path.basename(filepath)}") 
                else:
                    logger.error(f" 启动上传失败: {os.path.basename(filepath)}")
            except Exception as e:
                logger.error(f" 启动上传异常: {str(e)}")

    event_handler = FileHandler(config, tracker)
    observer = Observer()
    observer.schedule(event_handler, watch_path, recursive=False)
    observer.start()

    print(f" 监视目录: {watch_path}")
    print(" 输入 'm' 进入手动上传模式，Ctrl+C 退出程序。")

    try:
        while True:
            try:
                user_input = input()
            except EOFError:
                break
            if user_input.strip().lower() == 'm':
                manual_upload_prompt(tracker)
            else:
                time.sleep(1)
    except KeyboardInterrupt:
        print(" 退出程序。")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()

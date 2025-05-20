#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import time
import requests
import configparser
import logging
from tqdm import tqdm
from pathlib import Path

class FeishuUploader:
    def __init__(self, config_path='config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_path, encoding='utf-8')
        self._setup_logging()
        self.session = requests.Session()
        self._init_parameters()
        self._load_or_refresh_token()

    def _setup_logging(self):
        log_dir = 'log'
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger('FeishuUploader')
        self.logger.setLevel(logging.INFO)
        debug_logger = logging.getLogger('FeishuDebug')
        debug_logger.setLevel(logging.DEBUG)
        main_handler = logging.FileHandler(f'{log_dir}/upload.log')
        debug_handler = logging.FileHandler(f'{log_dir}/debug.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        main_handler.setFormatter(formatter)
        debug_handler.setFormatter(formatter)
        self.logger.addHandler(main_handler)
        debug_logger.addHandler(debug_handler)
        self.debug_logger = debug_logger

    def _init_parameters(self):
        self.chunk_size = self.config.getint('Feishu', 'chunk_size', fallback=4*1024*1024)
        self.debug_mode = self.config.getboolean('Feishu', 'debug_mode', fallback=False)
        self.base_url = self.config.get('Paths', 'base_url')
        self.token_file = self.config.get('Feishu', 'token_file', fallback='tokens.json')
        self.client_id = self.config.get('Feishu', 'client_id')
        self.client_secret = self.config.get('Feishu', 'client_secret')

    def _load_or_refresh_token(self):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not self._is_token_valid():
                    self.logger.info("Token无效或已过期，正在刷新...")
                    self._refresh_token()
                else:
                    self._load_token_headers()
                return
            except Exception as e:
                self.logger.error(f"Token加载失败: {str(e)}")
                if attempt == max_retries - 1:
                    raise Exception(f"无法获取有效Token: {str(e)}")
                time.sleep(2 ** attempt)

    def _is_token_valid(self):
        if not Path(self.token_file).exists():
            return False
        try:
            with open(self.token_file) as f:
                token_data = json.load(f)
            if 'access_token' not in token_data:
                return False
            if time.time() - os.path.getmtime(self.token_file) > 3600:
                return False
            self.access_token = token_data['access_token']
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "User-Agent": "FeishuUploader/2.0"
            })
            return True
        except:
            return False

    def _refresh_token(self):
        url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
        headers = {"Content-Type": "application/json"}
        data = {"app_id": self.client_id, "app_secret": self.client_secret}
        resp = requests.post(url, headers=headers, json=data, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") != 0:
            raise Exception(result.get("msg", "获取Token失败"))
        token_data = {
            "access_token": result["tenant_access_token"],
            "expire": result["expire"]
        }
        with open(self.token_file, 'w') as f:
            json.dump(token_data, f, indent=2)
        self.access_token = token_data["access_token"]
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "FeishuUploader/2.0"
        })

    def _load_token_headers(self):
        with open(self.token_file) as f:
            token_data = json.load(f)
        self.access_token = token_data["access_token"]
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "FeishuUploader/2.0"
        })

    def _debug_request(self, response):
        debug_info = (
            f"[DEBUG] 请求URL: {response.request.method} {response.request.url}\n"
            f"状态码: {response.status_code}\n"
            f"请求头: {dict(response.request.headers)}\n"
            f"响应预览: {response.text[:200]}...\n"
        )
        self.debug_logger.debug(debug_info)

    def get_root_folder_token(self):
        url = "https://open.feishu.cn/open-apis/drive/explorer/v2/root_folder/meta"
        try:
            resp = self.session.get(url)
            self._debug_request(resp)
            resp.raise_for_status()
            data = resp.json()
            if data.get("code") == 0:
                return data["data"]["token"]
            if data.get("code") == 99991668:
                self._refresh_token()
                return self.get_root_folder_token()
            raise Exception(f"获取根目录失败: {data.get('msg', '未知错误')}")
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                self._refresh_token()
                return self.get_root_folder_token()
            raise
        except Exception as e:
            self.logger.error(f"获取根目录异常: {str(e)}")
            raise

    def set_permission(self, file_token, file_type="file"):
        try:
            url = f"https://open.feishu.cn/open-apis/drive/v2/permissions/{file_token}/public?type={file_type}"
            permission_data = {
                "external_access_entity": self.config.get('Permissions', 'external_access_entity'),
                "security_entity": self.config.get('Permissions', 'security_entity'),
                "comment_entity": self.config.get('Permissions', 'comment_entity'),
                "link_share_entity": self.config.get('Permissions', 'link_share_entity')
            }
            resp = self.session.patch(url, json=permission_data)
            self._debug_request(resp)
            resp.raise_for_status()
            result = resp.json()
            if result.get("code") != 0:
                raise Exception(f"权限设置失败: {result.get('msg', '未知错误')}")
            return permission_data['external_access_entity']
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                self._refresh_token()
                return self.set_permission(file_token, file_type)
            raise
        except Exception as e:
            self.logger.error(f"设置权限异常: {str(e)}")
            return None

    def upload(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        self.logger.info(f"开始上传: {file_name} ({file_size/1024/1024:.2f}MB)")
        parent_node = self.get_root_folder_token()
        if not parent_node:
            raise Exception("无法获取根目录token")

        prepare_data = {
            "file_name": file_name,
            "parent_type": "explorer",
            "parent_node": parent_node,
            "size": file_size
        }

        prepare_resp = self.session.post(
            "https://open.feishu.cn/open-apis/drive/v1/files/upload_prepare",
            json=prepare_data
        )
        self._debug_request(prepare_resp)
        prepare_resp.raise_for_status()
        prepare_result = prepare_resp.json()
        if prepare_result.get("code") != 0:
            raise Exception(f"准备上传失败: {prepare_result.get('msg', '未知错误')}")

        upload_id = prepare_result["data"]["upload_id"]
        chunk_size = prepare_result["data"].get("block_size", self.chunk_size)
        
        with open(file_path, "rb") as f, tqdm(
            total=file_size, unit="B", unit_scale=True, desc="上传进度"
        ) as pbar:
            part_num = 0
            while chunk := f.read(chunk_size):
                for attempt in range(3):
                    try:
                        files = {
                            'upload_id': (None, upload_id),
                            'seq': (None, str(part_num)),
                            'size': (None, str(len(chunk))),
                            'file': (file_name, chunk, 'application/octet-stream')
                        }
                        part_resp = self.session.post(
                            "https://open.feishu.cn/open-apis/drive/v1/files/upload_part",
                            files=files
                        )
                        self._debug_request(part_resp)
                        part_resp.raise_for_status()
                        part_result = part_resp.json()
                        if part_result.get("code") != 0:
                            raise Exception(part_result.get("msg", "分片上传失败"))
                        break
                    except requests.HTTPError as e:
                        if e.response.status_code == 401 and attempt < 2:
                            self._refresh_token()
                            continue
                        raise
                    except Exception as e:
                        if attempt == 2:
                            raise
                        time.sleep(2 ** attempt)
                part_num += 1
                pbar.update(len(chunk))

        finish_resp = self.session.post(
            "https://open.feishu.cn/open-apis/drive/v1/files/upload_finish",
            json={"upload_id": upload_id, "block_num": part_num}
        )
        self._debug_request(finish_resp)
        finish_resp.raise_for_status()
        finish_result = finish_resp.json()
        if finish_result.get("code") != 0:
            raise Exception(finish_result.get("msg", "完成上传失败"))
        file_token = finish_result["data"]["file_token"]
        return {
            "name": os.path.splitext(file_name)[0],
            "token": file_token,
            "url": f"{self.base_url}{file_token}"
        }

def main(filepath=None):
    try:
        uploader = FeishuUploader()
        file_path = filepath if filepath else (sys.argv[1] if len(sys.argv) > 1 else input("请输入文件路径：").strip('"'))
        result = uploader.upload(file_path)
        permission_status = uploader.set_permission(result["token"])
        with open("URL.txt", "a", encoding="utf-8") as f:
            f.write(f"【权限】：{'外部' if permission_status == 'open' else '内部'}\n")
            f.write(f"【{result['name']}】【视频】：{result['url']}\n")
        print("上传成功！")
        print(f"【权限】：{'外部' if permission_status == 'open' else '内部'}")
        print(f"【{result['name']}】【视频】：{result['url']}\n")
        return True
    except Exception as e:
        print(f"上传失败: {str(e)}")
        if __name__ == "__main__":
            sys.exit(1)
        return False

if __name__ == "__main__":
    main()

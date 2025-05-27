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
        self.debug_mode = self.config.getboolean('Feishu', 'debug_mode', fallback=False) 
        self.logger = logging.getLogger('FeishuUploader')
        self.session = requests.Session()
        self._init_parameters()
        self._load_or_refresh_token()

    def _setup_logging(self):
        enable_logging = self.config.getboolean('Logging', 'enable_logging', fallback=True)
        debug_mode = self.debug_mode

        if not enable_logging:
            self.logger = None
            self.debug_logger = None
            return

        log_dir = 'log'
        os.makedirs(log_dir, exist_ok=True)

        self.logger = logging.getLogger('FeishuUploader')
        self.logger.setLevel(logging.INFO)
        debug_logger = logging.getLogger('FeishuDebug')
        debug_logger.setLevel(logging.DEBUG if debug_mode else logging.CRITICAL)

        formatter = logging.Formatter(
            '[%(asctime)s] - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        main_handler = logging.FileHandler(f'{log_dir}/upload.log')
        main_handler.setFormatter(formatter)
        self.logger.addHandler(main_handler)

        if debug_mode:
            debug_handler = logging.FileHandler(f'{log_dir}/debug.log')
            debug_handler.setFormatter(formatter)
            debug_logger.addHandler(debug_handler)
        else:
            debug_logger.handlers = []
            debug_logger.propagate = False

        self.debug_logger = debug_logger if debug_mode else None


    def _init_parameters(self):
        if not self.config.has_section('Feishu') or not self.config.has_section('Paths'):
            raise ValueError("配置文件缺少必要节段")

        self.chunk_size = self.config.getint('Feishu', 'chunk_size', fallback=4*1024*1024)
        self.base_url = self.config.get('Paths', 'base_url')
        self.token_file = self.config.get('Feishu', 'token_file', fallback='tokens.json')
        
        self.client_id = self.config.get('Feishu', 'client_id')
        self.client_secret = self.config.get('Feishu', 'client_secret')
        if not self.client_id or not self.client_secret:
            raise ValueError("client_id和client_secret必须配置")

        self.collaborator_id = self.config.get('Permissions', 'collaborator_id', fallback=None)
        self.collaborator_perm = self.config.get('Permissions', 'collaborator_perm', fallback='full_access')

        self.new_owner_id = self.config.get('Permissions', 'new_owner_id', fallback=None)
        self.transfer_ownership_flag = self.config.getboolean('Permissions', 'transfer_ownership', fallback=False)
        self.need_notification = self.config.getboolean('Permissions', 'need_notification', fallback=True)
        self.remove_old_owner = self.config.getboolean('Permissions', 'remove_old_owner', fallback=False)
        self.stay_put = self.config.getboolean('Permissions', 'stay_put', fallback=False)
    
        self.enable_ownership = self.config.getboolean(
        'Permissions', 'enable_ownership_transfer', fallback=True)
        self.enable_collaborator = self.config.getboolean(
        'Permissions', 'enable_collaborator', fallback=True)
  

    def add_collaborator(self, file_token, file_type="file"):
        if not self.collaborator_id:
            if self.logger: 
                self.logger.warning("未配置协作者ID，跳过添加协作者")
            return None
            
        url = f"https://open.feishu.cn/open-apis/drive/v1/permissions/{file_token}/members"
        params = {
            "type": file_type,
            "need_notification": "false"
        }
        data = {
            "member_id": self.collaborator_id,
            "member_type": "userid",
            "perm": self.collaborator_perm,
            "perm_type": "container",
            "type": "user"
        }

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json; charset=utf-8"
            }
            resp = self.session.post(url, params=params, json=data, headers=headers)
            self._debug_request(resp)
            resp.raise_for_status()
            result = resp.json()
            
            if result.get("code") != 0:
                error_msg = f"添加协作者失败: {result.get('msg')} (code: {result.get('code')})"
                if result.get("code") == 1063001:
                    if self.debug_mode and self.debug_logger:
                        self.debug_logger.debug(f"完整请求参数: {json.dumps(data, indent=2)}")
                        self.debug_logger.debug(f"API原始响应: {resp.text}")
                raise Exception(error_msg)
            
            if self.logger:
                self.logger.info(f"成功添加协作者: ID={self.collaborator_id} 类型={'openid' if self.collaborator_id.startswith('u-') else 'userid'} 权限={self.collaborator_perm}")
            return True
            
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                self._refresh_token()
                return self.add_collaborator(file_token, file_type)
            if self.logger:
                self.logger.error(f"HTTP错误 {e.response.status_code}: {e.response.text}")
            raise
        except Exception as e:
            if self.logger:
                self.logger.error(f"添加协作者异常: {str(e)}")
            if self.debug_mode and self.debug_logger:
                self.debug_logger.debug(f"完整请求头: {dict(self.session.headers)}")
                self.debug_logger.debug(f"请求正文: {data}")
            return False

    class RetryExhaustedError(Exception):
        pass

    def perform_ownership_transfer(self, file_token, file_type="file", retry_count=3):
        if retry_count <= 0:
            error_msg = f"所有权转移重试次数耗尽 (file_token: {file_token})"
            if self.logger:
                self.logger.error(error_msg)
            raise self.RetryExhaustedError(error_msg) 

        if not self.new_owner_id:
            if self.logger:
                self.logger.warning("未配置新所有者ID，跳过所有权转移")
            return False

        url = f"https://open.feishu.cn/open-apis/drive/v1/permissions/{file_token}/members/transfer_owner"
        params = {
            "type": file_type,
            "need_notification": str(self.need_notification).lower(),
            "remove_old_owner": str(self.remove_old_owner).lower(),
            "stay_put": str(self.stay_put).lower(),
            "old_owner_perm": "full_access"
        }
        data = {
            "member_id": self.new_owner_id,
            "member_type": "userid"
        }

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json; charset=utf-8"
            }
            resp = self.session.post(url, params=params, json=data, headers=headers)
            self._debug_request(resp)
            resp.raise_for_status()
            result = resp.json()
            
            if result.get("code") != 0:
                error_msg = f"所有权转移失败: {result.get('msg')} (code: {result.get('code')})"
                if self.logger:
                    self.logger.error(error_msg)
                raise Exception(error_msg)

            if self.logger:
                self.logger.info(f"成功转移所有权给: {self.new_owner_id}")
            return True

        except requests.HTTPError as e:
            if e.response.status_code == 401:
                if self.logger:
                    self.logger.warning(f"[安全机制] 检测到401错误，剩余重试次数: {retry_count-1}")
                try:
                    self._refresh_token()
                except Exception as refresh_error:
                    if self.logger:
                        self.logger.error(f"Token刷新失败: {str(refresh_error)}")
                    raise
                
                return self.perform_ownership_transfer(
                    file_token, 
                    file_type, 
                    retry_count=retry_count-1
                )
            else:
                error_msg = f"HTTP错误 {e.response.status_code}: {e.response.text}"
                if self.logger:
                    self.logger.error(error_msg)
                raise

        except Exception as e:
            error_msg = f"所有权转移过程异常: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            if self.debug_mode and self.debug_logger:
                self.debug_logger.debug(f"完整请求头: {dict(self.session.headers)}")
                self.debug_logger.debug(f"请求正文: {data}")
            raise

    def _load_or_refresh_token(self):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not self._is_token_valid():
                    if self.logger:
                        self.logger.info("Token无效或已过期，正在刷新...")
                    self._refresh_token()
                else:
                    self._load_token_headers()
                return
            except Exception as e:
                if self.logger:
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
            if 'access_token' not in token_data or 'expire' not in token_data:
                return False
            expire_time = token_data['expire']
            return time.time() < (expire_time - 600)
        except Exception:
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
            "expire": int(time.time()) + result["expire"] 
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
        if self.debug_mode and self.debug_logger: 
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
            if self.logger:
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
            if self.logger:
                self.logger.error(f"设置权限异常: {str(e)}")
            return None

    def upload(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        if self.logger:
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
            total=file_size, unit="B", unit_scale=True, desc=" 上传进度"
        ) as pbar:
            part_num = 0
            while chunk := f.read(chunk_size):
                for attempt in range(3):
                    try:
                        data = {
                            'upload_id': upload_id,
                            'seq': part_num,
                            'size': len(chunk)
                        }
                        part_resp = self.session.post(
                            "https://open.feishu.cn/open-apis/drive/v1/files/upload_part",
                            data=data,
                            files={'file': (file_name, chunk)}
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

        result = {
            "name": os.path.splitext(file_name)[0],
            "token": file_token,
            "url": f"{self.base_url}{file_token}",
            "permission": None,
            "collaborator": None,
            "new_owner": None
        }

        try:
            permission_status = self.set_permission(file_token)
            result["permission"] = '外部' if permission_status == 'open' else '内部'
        except Exception as e:
            if self.logger:
                self.logger.error(f"权限设置失败: {str(e)}")
            result["permission"] = '未设置'

        if self.enable_collaborator and self.collaborator_id:
            try:
                if self.add_collaborator(file_token):
                    result["collaborator"] = self.collaborator_id
            except Exception as e:
                if self.logger:
                    self.logger.error(f"添加协作者失败: {str(e)}")

        if self.enable_ownership and self.new_owner_id and self.transfer_ownership_flag:
            try:
                success = self.perform_ownership_transfer(
                    file_token=file_token,
                    file_type="file"
                )
                if success:
                    result["new_owner"] = self.new_owner_id
            except Exception as e:
                if self.logger:
                    self.logger.error(f"所有权转移失败: {str(e)}")

        return result

def main(filepath=None):
    try:
        uploader = FeishuUploader()
        file_path = filepath if filepath else (sys.argv[1] if len(sys.argv) > 1 else input("请输入文件路径：").strip('"'))
        result = uploader.upload(file_path)
        with open("URL.txt", "a", encoding="utf-8") as f:
            f.write(f"【权限】：{result['permission']}\n")
            f.write(f"【{result['name']}】【视频】：{result['url']}\n")
        print()
        print(f"\033[38;2;144;238;144m【权限】：{result['permission']}\033[0m", end='')
        transfer_info = []
        if result.get('new_owner'):
            transfer_info.append("\033[38;2;144;238;144m所有权转移成功\033[0m")
        if result.get('collaborator'):
            transfer_info.append("\033[38;2;144;238;144m协作者添加成功\033[0m")           
        if transfer_info:
            print(f" | {' | '.join(transfer_info)}", end='')
        print()
        print(f"\033[38;2;144;238;144m【{result['name']}】【视频】：{result['url']}\033[0m\n")
        return True
    except Exception as e:
        print(f"上传失败: {str(e)}")
        if __name__ == "__main__":
            sys.exit(1)
        return False

if __name__ == "__main__":
    main()

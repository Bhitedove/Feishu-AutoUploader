# 织梦字幕组飞书自动化上传脚本 （Feishu-AutoUploader）

## 功能介绍
 监控目标文件夹或手动上传文件至飞书云文档，并设定文档权限，提取分享链接。
 
## 使用说明
### 1. 编辑config.ini。
 首次使用请先运行```"Feishu AutoUploader.exe"```生成```config.ini```文件。
 如无法生成请使用```Code```里的```config.ini```。
 
>  ### [Feishu] 飞书配置
>  
> | 参数 | 说明 | 示例值 |
> |------|------|-------|
> | `watch_path` | 监控上传的文件夹路径 | `E:\Yumezukuri` |
> | `token_file` | 存储access_token的文件 | `tokens.json` |
> | `chunk_size` | 分片上传大小(字节) | `4194304` (4MB) |
> | `debug_mode` | 是否启用调试模式 | `true`/`false` |
> | `client_id` | 飞书应用ID | `cli_xxxxxx` |
> | `client_secret` | 飞书应用密钥 | `9GRTXGKKBV...` |
> 
> **`client` 相关为敏感信息，请妥善保管，并浏览自述文档中的```「关于安全性」```章节。  
> 我们并没有对敏感信息进行加密，  你需要自己承担评估任何风险。**
> 
> ### [Logging] 日志配置
> 
> | 参数 | 说明 | 示例值 |
> |------|------|-------|
> | `enable_logging` | 启用日志记录 | `true` |
> | `log_file` | 主日志文件名 | `feishu_uploader.log` |
> | `debug_log` | 调试日志文件名 | `debug.log` |
> | `log_level` | 日志级别 | `INFO` |
> | `state_file` | 上传状态记录文件 | `upload_state.json` |
> 
> 日志级别选项：`DEBUG` > `INFO` > `WARNING` > `ERROR`
> 
> ### [Rename] 文件重命名规则
> 匹配格式：```原始匹配正则=>替换表达式```。
> 
> | 参数 | 说明 | 示例值 |
> |------|------|-------|
> | `enabled` | 开启自动化文件重命名 | `true` |
> 
> ```ini
> enabled = true
> rules = \[.*?\]=>; \(.*?\)=>; - (\d+)=> E\1; ^(\d+)=> E\1; \s+=> 
> ```
> 
> ### [Permissions] 访问权限配置
> 
> 控制上传文件的访问权限设置：
> 
> | 配置项 | 可选值 | 默认值 | 说明 |
> |--------|--------|--------|------|
> | `external_access_entity` | `open`, `closed` | `open` | 是否允许外部访问 |
> | `security_entity` | `anyone_can_view`, `only_owner` | `anyone_can_view` | 查看权限 |
> | `comment_entity` | `anyone_can_view`, `only_owner` | `anyone_can_view` | 评论权限 |
> | `share_entity` | `anyone`, `only_owner` | `anyone` | 分享权限 |
> | `link_share_entity` | `anyone_readable`, `only_owner` | `anyone_readable` | 链接分享权限 |
> | `copy_entity` | `anyone_can_view`, `only_owner` | `anyone_can_view` | 复制/下载权限 |
> 
> ### 权限说明：
> - `open`：允许组织外用户访问
> - `closed`：仅组织内成员可见
> - `anyone_can_view`：有权限的用户可查看
> - `only_owner`：仅文件所有者有权限
> - `anyone_readable`：通过链接可查看内容
> 
> ### [Paths] 外部路径配置
> 
> | 配置项 | 示例 | 必填 | 说明 |
> |--------|------|------|------|
> | `base_url` | `https://[your-domain].feishu.cn/file/` | 是 | 文件分享基础URL |
> 


### 2. 运行方式

 默认打开使用自动模式，监视文件夹路径上传，你可按照提示输入```m```切换手动上传模式，并输入路径上传。

 或将你需要上传的文件拖拽至```"Feishu AutoUploader.exe"```即视为手动上传并直接使用拖拽路径执行手动上传，并在之后切换为自动上传。

 如需结束，请直接关闭掉运行窗口。


### 3. 关于安全性
本程序会在以下位置储存并管理你的token信息及敏感信息，请妥善保管```tokens.json```、```config.ini```、```log```。  
请注意该程序还有可能在```log```中存储，如该操作不是你想要的请关闭记录日志的相关配置。  
我们不对有关程序和自述文件等任何有关项目文件做有效保证，请自行评估有可能存在的安全和错误的风险。

### 4. 联动场景
使用RSS订阅配合本程序完成自动化上传，以及更多由你创造的联动场景。

### 5. 相关文档说明附录
> 飞书开发平台```https://open.feishu.cn/app```。

> 飞书开发文档```https://open.feishu.cn/document/home/index```。

任何飞书的相关权限以及错误码等相关问题，你都可在飞书开发文档中找到。

以下为我们使用的权限，你可在```飞书开发平台 - 自建应用 - 权限管理 - 批量导入/导出权限```复制粘贴完成飞书权限配置。  
此权限仅为织梦字幕组所推荐的权限，不代表任何用户所需要的权限，仅作参考，我们不对文章任何内容做准确性保证。
```
{
  "scopes": {
    "tenant": [
      "bitable:app",
      "bitable:app:readonly",
      "drive:drive",
      "drive:drive.metadata:readonly",
      "drive:drive.search:readonly",
      "drive:drive:readonly",
      "drive:drive:version",
      "drive:drive:version:readonly",
      "drive:export:readonly",
      "drive:file",
      "drive:file.like:readonly",
      "drive:file.meta.sec_label.read_only",
      "drive:file:download",
      "drive:file:readonly",
      "drive:file:upload",
      "drive:file:view_record:readonly",
      "event:ip_list"
    ],
    "user": [
      "contact:user.employee_id:readonly",
      "docs:doc",
      "docs:permission.setting:write_only",
      "docx:document",
      "drive:drive",
      "drive:drive:readonly",
      "drive:file",
      "drive:file:upload",
      "offline_access",
      "sheets:spreadsheet",
      "space:document:retrieve",
      "wiki:wiki"
    ]
  }
}
```

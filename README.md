# 适用于 Microsoft Agent Framework 的 Container Apps 代码解释器

这是适用于 Microsoft Agent Framework 的 Azure Container Apps 动态会话 Python 代码解释器工具。`SessionsPythonTool` 将 Azure Container Apps 动态会话与 Microsoft Agent Framework 集成，使 AI 代理工作流能够安全地执行 Python 代码。

- 在安全、隔离的 Azure Container Apps 会话中执行 Python 代码
- 内置安全机制，支持可配置的文件上传/下载限制
- 与 Microsoft Agent Framework 无缝集成

## 前提条件

1. **Azure Container Apps 动态会话池**：您需要设置 Azure Container Apps 会话池。请参照 [Azure 文档](https://learn.microsoft.com/zh-cn/azure/container-apps/sessions-code-interpreter) 创建会话池。

2. **Azure 角色分配**：访问动态会话需要将 `Azure ContainerApps Session Executor` 角色分配给您选择的身份（用户、服务主体、托管标识）。对于当前用户：

```bash
az role assignment create \
  --role "Azure ContainerApps Session Executor" \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --scope /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.App/sessionPools/<pool-name>
```

3. **填写 Dot Env 文件**：将 `.env.example` 复制为 `.env`，并填写以下环境变量。
```bash
AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT=https://{REGION}.dynamicsessions.io/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/sessionPools/${SESSION_POOL_NAME}
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
```

## 快速开始

### 与 Microsoft Agent Framework 配合使用

将代码解释器与 AI 代理集成，实现自然语言代码执行：

```python
import asyncio
from azure.identity import DefaultAzureCredential
from agent_framework.azure import AzureOpenAIChatClient
from maf_code_interpreter import SessionsPythonTool

async def main():
    # 创建代码解释器工具
    sessions_tool = SessionsPythonTool(
        pool_management_endpoint="YOUR_POOL_ENDPOINT",
        credential=DefaultAzureCredential()
    )
    
    # 使用工具创建 AI 代理
    agent = AzureOpenAIChatClient(
        credential=DefaultAzureCredential()
    ).create_agent(
        instructions="""您是一位拥有 Python 代码解释器访问权限的助手。
        您可以执行 Python 代码来帮助用户进行计算、数据分析等操作。""",
        tools=sessions_tool  # 直接传递工具，无需包装！
    )
    
    # 让代理执行计算
    result = await agent.run(
        "计算 [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] 的均值和标准差"
    )
    print(result)

asyncio.run(main())
```

## 示例

请查看 `examples/` 目录中的示例：

- `basic_usage.py`：演示 SessionsPythonTool 与 Microsoft Agent Framework 的集成 - `uv run python examples/basic_usage.py`

- `file_operations.py`：展示如何通过动态会话和 MAF 向会话上传文件、使用 Python 代码处理文件以及下载结果 - `uv run python examples/file_operations.py`

## 配置

### 文件上传/下载安全

出于安全考虑，文件上传默认处于禁用状态。要启用文件上传：

```python
tool = SessionsPythonTool(
    pool_management_endpoint="...",
    credential=DefaultAzureCredential(),
    enable_dangerous_file_uploads=True,
    allowed_upload_directories={"/tmp/uploads"},
    allowed_download_directories={"/tmp/downloads"},
)
```

## API 参考

### 方法

- `execute_code(code: str) -> str`：执行 Python 代码并返回结果
- `upload_file(local_file_path: str, remote_file_path: str | None) -> SessionsRemoteFileMetadata`：上传文件
- `download_file_to_path(remote_file_name: str, local_file_path: str) -> str`：下载文件并保存到本地路径
- `download_file_to_bytes(remote_file_name: str) -> BytesIO`：以 BytesIO 对象形式下载文件
- `list_files() -> list[SessionsRemoteFileMetadata]`：列出会话中的文件

## 相关项目

- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework)：统一的 AI 代理框架
- [Azure Container Apps](https://learn.microsoft.com/zh-cn/azure/container-apps/)：Microsoft 的无服务器容器平台
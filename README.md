# Container Apps Code Interpreter for Microsoft Agent Framework

This is Azure Container Apps Dynamic Sessions Python Code Interpreter Tool for Microsoft Agent Framework.  `SessionsPythonTool` that integrates Azure Container Apps Dynamic Sessions with Microsoft Agent Framework, enabling secure Python code execution in AI agent workflows.

- Execute Python code in secure, isolated Azure Container Apps sessions
- Built-in security with configurable file upload/download restrictions
- Seamless integration with Microsoft Agent Framework

## Prerequisites

1. **Azure Container Apps Dynamic Session Pool**: You need to set up an Azure Container Apps Session Pool. Follow the [Azure documentation](https://learn.microsoft.com/en-us/azure/container-apps/sessions-code-interpreter) to create one.

2. **Azure Role Assignment**: Accessing Dynamcis Sessions requires the role `Azure ContainerApps Session Executor` to your choice of Identity - User, Service Principal, Managed Identity. For the current user:

```bash
az role assignment create \
  --role "Azure ContainerApps Session Executor" \
  --assignee $(az ad signed-in-user show --query id -o tsv) \
  --scope /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.App/sessionPools/<pool-name>
```

3. **Populate Dot Env**: Copy the `.env.example` to `.env` and populate the following environment variables.
```bash
AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT=https://{REGION}.dynamicsessions.io/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/sessionPools/${SESSION_POOL_NAME}
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
```

## Quick Start

### Using with Microsoft Agent Framework

Integrate the code interpreter with AI agents for natural language code execution:

```python
import asyncio
from azure.identity import DefaultAzureCredential
from agent_framework.azure import AzureOpenAIChatClient
from maf_code_interpreter import SessionsPythonTool

async def main():
    # Create the code interpreter tool
    sessions_tool = SessionsPythonTool(
        pool_management_endpoint="YOUR_POOL_ENDPOINT",
        credential=DefaultAzureCredential()
    )
    
    # Create an AI agent with the tool
    agent = AzureOpenAIChatClient(
        credential=DefaultAzureCredential()
    ).create_agent(
        instructions="""You are a helpful assistant with access to a Python code interpreter.
        You can execute Python code to help users with calculations, data analysis, and more.""",
        tools=sessions_tool  # Pass the tool directly - no wrapper needed!
    )
    
    # Ask the agent to perform calculations
    result = await agent.run(
        "Calculate the mean and standard deviation of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"
    )
    print(result)

asyncio.run(main())
```

## Examples

Check out the `examples/` directory for examples:

- `basic_usage.py`: Demonstrates SessionsPythonTool integrating with Microsoft Agent Framework - `uv run python examples/basic_usage.py`

- `file_operations.py`: Shows how to upload files to sessions, process them with Python code, and download results with Dynamic Sessions and MAF - `uv run python examples/file_operations.py`

## Configuration

### File Upload/Download Security

By default, file uploads are disabled for security. To enable:

```python
tool = SessionsPythonTool(
    pool_management_endpoint="...",
    credential=DefaultAzureCredential(),
    enable_dangerous_file_uploads=True,
    allowed_upload_directories={"/tmp/uploads"},
    allowed_download_directories={"/tmp/downloads"},
)
```

## API Reference

### Methods

- `execute_code(code: str) -> str`: Execute Python code and return results
- `upload_file(local_file_path: str, remote_file_path: str | None) -> SessionsRemoteFileMetadata`: Upload a file
- `download_file_to_path(remote_file_name: str, local_file_path: str) -> str`: Download a file and save to local path
- `download_file_to_bytes(remote_file_name: str) -> BytesIO`: Download a file as a BytesIO object
- `list_files() -> list[SessionsRemoteFileMetadata]`: List files in the session

## Related Projects

- [Microsoft Agent Framework](https://github.com/microsoft/agent-framework): Unified framework for AI agents
- [Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/): Microsoft's serverless container platform
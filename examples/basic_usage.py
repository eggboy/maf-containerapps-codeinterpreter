import asyncio
import os
from pathlib import Path

from agent_framework.azure import AzureOpenAIChatClient
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv

from maf_code_interpreter import SessionsPythonTool

# Load .env from project root (parent directory)
load_dotenv(Path(__file__).parent.parent / ".env")


async def main():
    """Example demonstrating SessionsPythonTool with Microsoft Agent Framework."""
    pool_endpoint = os.getenv("AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT")

    # Initialize the SessionsPythonTool with Azure credentials
    credential = DefaultAzureCredential()

    sessions_tool = SessionsPythonTool(
        pool_management_endpoint=pool_endpoint,
        credential=credential,
        # Optional: Configure file upload/download restrictions
        # enable_dangerous_file_uploads=True,
        # allowed_upload_directories={"/tmp"},
        # allowed_download_directories={"/tmp"},
    )

    # SessionsPythonTool can be passed directly as a tool — no wrapper function needed.
    # MAF auto-converts it via its __call__ method.
    agent = AzureOpenAIChatClient(credential=DefaultAzureCredential()).create_agent(
        instructions="""You are a helpful assistant with access to a Python code interpreter.
        You can execute Python code to help users with calculations, data analysis, and more.
        Always explain what the code will do before executing it.""",
        tools=sessions_tool,
    )

    # Example 1: Simple calculation
    print("\n=== Example 1: Simple Calculation ===")
    result = await agent.run("use the python tool to calculate 12345 * 67890?")
    print(f"Result: {result}")

    # Example 2: Data analysis
    print("\n=== Example 2: Data Analysis ===")
    result = await agent.run(
        "use the python tool to Calculate the mean and standard deviation of the list: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"
    )
    print(f"Result: {result}")

    # Example 3: Generate data
    print("\n=== Example 3: Generate Plot Data ===")
    result = await agent.run("use the python tool toGenerate 10 random numbers between 1 and 100 and show their sum")
    print(f"Result: {result}")

    # Example 4: Working with libraries
    print("\n=== Example 4: Using NumPy ===")
    result = await agent.run(
        "use the python tool with numpy to create a 3x3 identity matrix and calculate its determinant"
    )
    print(f"Result: {result}")


async def direct_tool_usage_example():
    """Example of using SessionsPythonTool directly without an agent."""
    print("\n=== Direct Tool Usage Example ===")

    # Initialize the tool
    pool_endpoint = os.getenv("AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT")

    credential = DefaultAzureCredential()

    sessions_tool = SessionsPythonTool(
        pool_management_endpoint=pool_endpoint,
        credential=credential,
    )

    # Execute code directly
    code = """
import math

# Calculate factorial of 10
result = math.factorial(10)
print(f"10! = {result}")
result
"""

    result = await sessions_tool.execute_code(code)
    print(f"Execution Result:\n{result}")

    # List files in the session
    files = await sessions_tool.list_files()
    print(f"\nFiles in session: {len(files)}")
    for file in files:
        print(f"  - {file.filename} ({file.size_in_bytes} bytes)")


if __name__ == "__main__":
    asyncio.run(main())
    asyncio.run(direct_tool_usage_example())

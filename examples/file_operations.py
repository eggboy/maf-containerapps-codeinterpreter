import asyncio
import os
import tempfile
from pathlib import Path

import aiofiles
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv

from maf_code_interpreter import SessionsPythonTool

load_dotenv(Path(__file__).parent.parent / ".env")


async def file_operations_example():
    """Example demonstrating file upload, processing, and download."""
    print("\n=== File Operations Example ===\n")

    # Create a temporary directory for our test files
    temp_dir = tempfile.mkdtemp()

    # Initialize the tool with file upload/download enabled
    pool_endpoint = os.getenv("AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT")

    credential = DefaultAzureCredential()

    sessions_tool = SessionsPythonTool(
        pool_management_endpoint=pool_endpoint,
        credential=credential,
        enable_dangerous_file_uploads=True,
        allowed_upload_directories={temp_dir},
        allowed_download_directories={temp_dir},
    )

    try:
        # 1. Create a sample CSV file locally
        print("\n1. Creating sample CSV file...")
        csv_path = Path(temp_dir) / "sample_data.csv"
        async with aiofiles.open(csv_path, "w") as f:
            await f.write("name,age,score\n")
            await f.write("Alice,25,95\n")
            await f.write("Bob,30,87\n")
            await f.write("Charlie,35,92\n")
            await f.write("Diana,28,89\n")
        print(f"   Created: {csv_path}")

        # 2. Upload the file to the session
        print("\n2. Uploading file to session...")
        file_metadata = await sessions_tool.upload_file(
            local_file_path=str(csv_path), remote_file_path="sample_data.csv"
        )
        print(f"   Uploaded: {file_metadata.filename} ({file_metadata.size_in_bytes} bytes)")

        # 3. List files in the session
        print("\n3. Listing files in session...")
        files = await sessions_tool.list_files()
        print(f"   Found {len(files)} file(s):")
        for file in files:
            print(f"   - {file.filename}: {file.size_in_bytes} bytes at {file.full_path}")

        # 4. Process the file using Python code
        print("\n4. Processing file with pandas...")
        code = """
import pandas as pd

# Read the CSV file
df = pd.read_csv('/mnt/data/sample_data.csv')

# Calculate statistics
stats = {
    'mean_age': df['age'].mean(),
    'mean_score': df['score'].mean(),
    'max_score': df['score'].max(),
    'min_score': df['score'].min(),
}

print(f"Statistics:")
print(f"  Mean age: {stats['mean_age']:.1f}")
print(f"  Mean score: {stats['mean_score']:.1f}")
print(f"  Max score: {stats['max_score']}")
print(f"  Min score: {stats['min_score']}")

# Create a new file with processed data
df['grade'] = df['score'].apply(lambda x: 'A' if x >= 90 else 'B' if x >= 80 else 'C')
df.to_csv('/mnt/data/results.csv', index=False)

print("\\nProcessed data saved to results.csv")
stats
"""
        result = await sessions_tool.execute_code(code)
        print(f"   Execution result:\n{result}")

        # 5. Download the processed file
        print("\n5. Downloading processed file...")
        download_path = Path(temp_dir) / "results.csv"
        await sessions_tool.download_file(remote_file_name="results.csv", local_file_path=str(download_path))
        print(f"   Downloaded to: {download_path}")

        # 6. Read and display the downloaded file
        print("\n6. Contents of downloaded file:")
        async with aiofiles.open(download_path) as f:
            print(await f.read())

    finally:
        # Cleanup
        print("\n7. Cleaning up temporary files...")
        import shutil

        shutil.rmtree(temp_dir)
        print("   Done!")


async def data_visualization_example():
    """Example showing how to create and download a plot."""
    print("\n=== Data Visualization Example ===\n")

    temp_dir = tempfile.mkdtemp()
    pool_endpoint = os.getenv("AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT")

    credential = DefaultAzureCredential()

    sessions_tool = SessionsPythonTool(
        pool_management_endpoint=pool_endpoint,
        credential=credential,
        allowed_download_directories={temp_dir},
    )

    try:
        # Create a plot
        print("\n1. Creating a plot with matplotlib...")
        code = """
import matplotlib.pyplot as plt
import numpy as np

# Generate data
x = np.linspace(0, 10, 100)
y1 = np.sin(x)
y2 = np.cos(x)

# Create plot
plt.figure(figsize=(10, 6))
plt.plot(x, y1, label='sin(x)', linewidth=2)
plt.plot(x, y2, label='cos(x)', linewidth=2)
plt.xlabel('x')
plt.ylabel('y')
plt.title('Sine and Cosine Functions')
plt.legend()
plt.grid(True, alpha=0.3)

# Save the plot
plt.savefig('/mnt/data/plot.png', dpi=150, bbox_inches='tight')
print("Plot saved to /mnt/data/plot.png")

"Plot created successfully"
"""
        result = await sessions_tool.execute_code(code)
        print(f"   Result: {result}")

        # Download the plot
        print("\n2. Downloading the plot...")
        plot_path = Path(temp_dir) / "plot.png"
        await sessions_tool.download_file(remote_file_name="plot.png", local_file_path=str(plot_path))
        print(f"   Downloaded to: {plot_path}")
        print(f"   File size: {plot_path.stat().st_size} bytes")

    finally:
        # # Cleanup
        # print("\n3. Cleaning up...")
        # import shutil

        # shutil.rmtree(temp_dir)
        print("   Done!")


if __name__ == "__main__":
    asyncio.run(file_operations_example())

    asyncio.run(data_visualization_example())

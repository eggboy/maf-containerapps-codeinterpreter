import uuid

import pytest


def test_import_package():
    """Test that the package can be imported."""
    from maf_code_interpreter import (
        ACASessionsSettings,
        SessionsPythonSettings,
        SessionsPythonTool,
        SessionsRemoteFileMetadata,
    )

    assert SessionsPythonTool is not None
    assert SessionsPythonSettings is not None
    assert ACASessionsSettings is not None
    assert SessionsRemoteFileMetadata is not None


def test_sessions_python_settings():
    """Test SessionsPythonSettings creation."""
    from maf_code_interpreter import SessionsPythonSettings

    settings = SessionsPythonSettings()
    # Default session_id should be a valid UUID (generated per instance)
    uuid.UUID(settings.session_id)  # raises ValueError if not a valid UUID
    assert settings.sanitize_input is True

    # Each instance gets a unique session_id
    settings2 = SessionsPythonSettings()
    assert settings.session_id != settings2.session_id

    # Test with custom values
    custom_settings = SessionsPythonSettings(session_id="test-session", sanitize_input=False)
    assert custom_settings.session_id == "test-session"
    assert custom_settings.sanitize_input is False


def test_remote_file_metadata():
    """Test SessionsRemoteFileMetadata creation."""
    from maf_code_interpreter import SessionsRemoteFileMetadata

    metadata = SessionsRemoteFileMetadata(filename="test.txt", size_in_bytes=100, full_path="/mnt/data/test.txt")
    assert metadata.filename == "test.txt"
    assert metadata.size_in_bytes == 100
    assert metadata.full_path == "/mnt/data/test.txt"

    # Test from_dict
    data = {
        "filename": "data.csv",
        "sizeInBytes": 1024,
        "fullPath": "/mnt/data/data.csv",
    }
    metadata_from_dict = SessionsRemoteFileMetadata.from_dict(data)
    assert metadata_from_dict.filename == "data.csv"
    assert metadata_from_dict.size_in_bytes == 1024
    assert metadata_from_dict.full_path == "/mnt/data/data.csv"


def test_aca_settings_validation():
    """Test ACASessionsSettings validation."""
    from maf_code_interpreter import ACASessionsSettings

    # Should raise ValueError if no endpoint is provided
    with pytest.raises(ValueError, match="pool_management_endpoint must be provided"):
        ACASessionsSettings()


def test_sessions_python_tool_init_without_endpoint():
    """Test SessionsPythonTool initialization without endpoint."""
    from maf_code_interpreter import SessionsPythonTool

    # Should raise ValueError due to missing endpoint
    with pytest.raises(ValueError, match="pool_management_endpoint must be provided"):
        SessionsPythonTool()


def test_sessions_python_tool_is_callable():
    """Test that SessionsPythonTool instances are callable (for direct MAF tool usage)."""
    import inspect

    from maf_code_interpreter import SessionsPythonTool

    tool = SessionsPythonTool(
        pool_management_endpoint="https://test.azurecontainerapps.io",
        auth_callback=lambda: "fake-token",
    )

    # Instance is callable
    assert callable(tool)

    # __name__ is set so MAF generates a meaningful tool name
    assert tool.__name__ == "execute_python_code"

    # __call__ has the right signature for MAF to introspect
    sig = inspect.signature(tool.__call__)
    assert "code" in sig.parameters
    param = sig.parameters["code"]
    assert param.annotation is not inspect.Parameter.empty


def test_sessions_python_tool_has_docstring():
    """Test that __call__ has a docstring (used as tool description by MAF)."""
    from maf_code_interpreter import SessionsPythonTool

    tool = SessionsPythonTool(
        pool_management_endpoint="https://test.azurecontainerapps.io",
        auth_callback=lambda: "fake-token",
    )

    assert tool.__call__.__doc__ is not None
    assert "Python code" in tool.__call__.__doc__


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

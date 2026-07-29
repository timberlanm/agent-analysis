from pathlib import Path

from backend.services import incident_service


def test_runtime_path_defaults_to_declared_path(monkeypatch, tmp_path):
    monkeypatch.delenv("SOC_TEST_RUNTIME_PATH", raising=False)
    default = tmp_path / "default"
    assert (
        incident_service._configured_runtime_path(
            "SOC_TEST_RUNTIME_PATH",
            default,
        )
        == default.resolve()
    )


def test_relative_runtime_path_is_project_root_relative(monkeypatch):
    monkeypatch.setenv("SOC_TEST_RUNTIME_PATH", "runtime/data")
    expected = (
        incident_service.BASE_DIR.parent / Path("runtime/data")
    ).resolve()
    assert (
        incident_service._configured_runtime_path(
            "SOC_TEST_RUNTIME_PATH",
            incident_service.BASE_DIR / "unused",
        )
        == expected
    )


def test_absolute_runtime_path_is_preserved(monkeypatch, tmp_path):
    configured = tmp_path / "runtime-data"
    monkeypatch.setenv("SOC_TEST_RUNTIME_PATH", str(configured))
    assert (
        incident_service._configured_runtime_path(
            "SOC_TEST_RUNTIME_PATH",
            incident_service.BASE_DIR / "unused",
        )
        == configured.resolve()
    )

"""Unittests for OSV wrapper."""

from agent import osv_wrapper
from pytest_mock import plugin


def testOSVWrapper_withValidLockFile_returnTrue(valid_lock_file_content: bytes) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVFileHandler(valid_lock_file_content, None)
    assert osv_scanner_wrapper.set_extension_and_check_if_valid_lock_file() is True


def testOSVWrapper_withEmptyLockFile_returnFalse(
    invalid_lock_file_content: bytes,
) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVFileHandler(invalid_lock_file_content, None)
    assert osv_scanner_wrapper.set_extension_and_check_if_valid_lock_file() is False


def testOSVWrapper_withInvalidLockFile_returnFalse() -> None:
    osv_scanner_wrapper = osv_wrapper.OSVFileHandler(
        b"invalid_lock_file_content", "/invalid/lock/file/path.foo"
    )
    assert osv_scanner_wrapper.set_extension_and_check_if_valid_lock_file() is False


def testOSVWrapper_withLockFilePath_returnFileType(
    valid_lock_file_path: str
) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVFileHandler(None, valid_lock_file_path)
    assert osv_scanner_wrapper.get_file_type() == ".lock"


def testOSVWrapper_withLockFileContent_returnFileType(
    mocker: plugin.MockerFixture, valid_lock_file_content: bytes
) -> None:
    from_buffer_mock = mocker.patch("agent.osv_wrapper.magic.from_buffer")
    from_buffer_mock.return_value = "text/plain"
    osv_scanner_wrapper = osv_wrapper.OSVFileHandler(valid_lock_file_content, None)
    assert osv_scanner_wrapper.get_file_type() == ".txt"

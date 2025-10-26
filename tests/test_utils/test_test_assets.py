#!/usr/bin/env pytest
"""
Test suite for verifying test assets in tests/resources.
"""

import pytest
from pathlib import Path
from PIL import Image, UnidentifiedImageError

# —————————————————————————————————————————————————————————————————————
# Configuration
# —————————————————————————————————————————————————————————————————————
RESOURCES_DIR = Path("tests/resources")
BLANK_FILENAME = "blank.png"
INVALID_FILENAME = "invalid_file.png"
TEST_OCR_FILENAME = "test_ocr.png"
EXPECTED_BLANK_SIZE = (300, 100)
EXPECTED_BLANK_MODE = "RGB"

# —————————————————————————————————————————————————————————————————————
# Fixtures
# —————————————————————————————————————————————————————————————————————
@pytest.fixture(scope="module")
def resources_dir() -> Path:
    """
    Ensure the resources directory exists and return its Path.
    """
    assert RESOURCES_DIR.is_dir(), f"❌ Resources directory not found: {RESOURCES_DIR}"
    return RESOURCES_DIR

# —————————————————————————————————————————————————————————————————————
# Tests
# —————————————————————————————————————————————————————————————————————
def test_blank_image_exists_and_has_correct_properties(resources_dir: Path):
    """
    Verify that 'blank.png' exists, is a valid image, and has the expected size and mode.
    """
    path = resources_dir / BLANK_FILENAME
    assert path.exists(), f"❌ '{BLANK_FILENAME}' is missing"

    # Verify file integrity
    with Image.open(path) as img:
        img.verify()

    # Re-open to inspect properties
    with Image.open(path) as img:
        assert img.size == EXPECTED_BLANK_SIZE, (
            f"❌ '{BLANK_FILENAME}' size expected {EXPECTED_BLANK_SIZE}, got {img.size}"
        )
        assert img.mode == EXPECTED_BLANK_MODE, (
            f"❌ '{BLANK_FILENAME}' mode expected {EXPECTED_BLANK_MODE}, got {img.mode}"
        )

def test_invalid_file_raises_unidentified_image(resources_dir: Path):
    """
    Verify that opening 'invalid_file.png' raises an UnidentifiedImageError.
    """
    path = resources_dir / INVALID_FILENAME
    assert path.exists(), f"❌ '{INVALID_FILENAME}' is missing"

    with pytest.raises(UnidentifiedImageError):
        with Image.open(path) as img:
            img.verify()

def test_test_ocr_file_exists(resources_dir: Path):
    """
    Ensure that 'test_ocr.png' is present in the resources.
    """
    path = resources_dir / TEST_OCR_FILENAME
    assert path.exists(), f"❌ '{TEST_OCR_FILENAME}' is missing"

@pytest.mark.parametrize("filename", ["not_exists.png", "ghost_file.png"])
def test_nonexistent_files_do_not_exist(resources_dir: Path, filename: str):
    """
    Verify that specified non-existent filenames are indeed absent.
    """
    path = resources_dir / filename
    assert not path.exists(), (
        f"⚠️ '{filename}' should NOT exist, but it was found at {path}"
    )

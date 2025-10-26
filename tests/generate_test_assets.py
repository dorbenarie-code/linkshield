#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
from typing import Tuple
from PIL import Image

# —————————————————————————————————————————————————————————————————————
# Configuration
# —————————————————————————————————————————————————————————————————————
DEFAULT_RESOURCES_DIR: Path = Path("tests/resources")
BLANK_IMAGE_NAME: str = "blank.png"
INVALID_FILE_NAME: str = "invalid_file.png"
BLANK_IMAGE_SIZE: Tuple[int, int] = (300, 100)
BLANK_IMAGE_COLOR: str = "white"
INVALID_FILE_CONTENT: str = "This is not an image!"

# —————————————————————————————————————————————————————————————————————
# Logger setup
# —————————————————————————————————————————————————————————————————————
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# —————————————————————————————————————————————————————————————————————
# Helpers
# —————————————————————————————————————————————————————————————————————
def ensure_resources_dir(path: Path) -> None:
    """
    Ensure that the resources directory exists.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        logger.debug("Ensured resources directory exists: %s", path)
    except Exception as e:
        logger.error("Failed to create resources directory %s: %s", path, e)
        raise

def create_blank_image(
    resources_dir: Path,
    filename: str = BLANK_IMAGE_NAME,
    size: Tuple[int, int] = BLANK_IMAGE_SIZE,
    color: str = BLANK_IMAGE_COLOR,
) -> Path:
    """
    Create a blank PNG image of the given size and color.
    """
    path = resources_dir / filename
    try:
        img = Image.new("RGB", size, color)
        img.save(path)
        logger.info("✅ Created blank image at %s", path)
        return path
    except Exception as e:
        logger.error("Failed to create blank image %s: %s", path, e)
        raise

def create_invalid_file(
    resources_dir: Path,
    filename: str = INVALID_FILE_NAME,
    content: str = INVALID_FILE_CONTENT,
) -> Path:
    """
    Create a non-image file using a .png extension to simulate a corrupt image.
    """
    path = resources_dir / filename
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("✅ Created invalid image file at %s", path)
        return path
    except Exception as e:
        logger.error("Failed to create invalid file %s: %s", path, e)
        raise

# —————————————————————————————————————————————————————————————————————
# Main
# —————————————————————————————————————————————————————————————————————
def main(resources_dir: Path = DEFAULT_RESOURCES_DIR) -> None:
    """
    Generate all test assets: a blank image and a fake image file.
    """
    try:
        ensure_resources_dir(resources_dir)
        create_blank_image(resources_dir)
        create_invalid_file(resources_dir)
        logger.info("🚀 All test assets created successfully.")
    except Exception:
        logger.exception("❌ Error generating test assets")
        sys.exit(1)

if __name__ == "__main__":
    main()

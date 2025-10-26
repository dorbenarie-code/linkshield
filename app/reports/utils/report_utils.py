from pathlib import Path
from weasyprint import HTML
import logging
from pathlib import Path
import secrets
from typing import Union, Tuple
import logging
from PIL import Image, ImageDraw, ImageFont
import tempfile 

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
BASE_DIR = Path(__file__).parent.parent.resolve()
class SafeWriteError(Exception):
    """Raised when safe_write operation fails or is unsafe."""




def export_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """
    Convert an HTML file to PDF and save it.

    Params:
        html_path (Path): Path to the source HTML file.
        pdf_path  (Path): Desired output PDF path.

    Returns:
        bool: True if export succeeded, False otherwise.
    """
    try:
        # 1. Verify source exists
        if not html_path.is_file():
            logger.error("Source HTML not found: %s", html_path)
            return False

        # 2. Ensure output directory exists
        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        # 3. Perform conversion
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))

        # 4. Log success
        logger.info("📄 PDF exported to: %s", pdf_path.resolve())
        return True

    except Exception:
        # Logs full traceback for easier debugging
        logger.exception("❌ Failed to export PDF from %s to %s", html_path, pdf_path)
        return False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BASE_DIR = Path(__file__).parent.resolve()

def generate_screenshot(
    target: Union[Path, str],
    text: str = "LinkShield Test Screenshot",
    size: Tuple[int, int] = (600, 300),
    noise_ratio: float = 0.02,
) -> Path:
    """
    Generate a PNG image with centered text, random background & noise.

    Args:
        target (Path | str): Directory under which to place the screenshot
            or file‐path relative to BASE_DIR.
        text (str): Label to render at the center.
        size ((int, int)): Width and height in pixels.
        noise_ratio (float): Fraction of pixels to sprinkle with random noise.

    Returns:
        Path: Absolute path to the saved PNG.

    Raises:
        ValueError: If safe_path_under rejects the output path.
        OSError: On failure to write the image.
    """
    # Step 1: Determine default screenshot folder when target is a dir, empty, '.', or None
    if Path(target).is_dir() or target in ("", ".", None):
        # generate a unique filename
        filename = f"screenshot_{secrets.token_hex(8)}.png"
        # force central default under BASE_DIR/reports/screenshots
        raw_path = BASE_DIR / "reports" / "screenshots" / filename
    else:
        # if user provided a specific file path (relative), honor it
        raw_path = BASE_DIR / str(target)

    # validate the resolved path is under BASE_DIR
    out_path = safe_path_under(BASE_DIR, raw_path)
    # ensure parent directory exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    width, height = size
    # Create base image with random background
    bg_color = tuple(secrets.randbelow(256) for _ in range(3))
    image = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # Add random noise pixels
    total_pixels = width * height
    noise_count = int(total_pixels * noise_ratio)
    for _ in range(noise_count):
        x = secrets.randbelow(width)
        y = secrets.randbelow(height)
        noise_color = tuple(secrets.randbelow(256) for _ in range(3))
        draw.point((x, y), fill=noise_color)

    # Load font, fallback to default if needed
    try:
        font = ImageFont.truetype("arial.ttf", size=24)
    except (OSError, IOError):
        font = ImageFont.load_default()

    # Calculate text size and center coordinates
    bbox = draw.textbbox((0, 0), text, font=font)
    text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (width - text_w) // 2
    y = (height - text_h) // 2

    # Select contrasting text color (white on dark bg, black on light bg)
    luminance = sum(bg_color) / 3
    text_color = "#FFFFFF" if luminance < 128 else "#000000"

    # Render the text onto the image
    draw.text((x, y), text, font=font, fill=text_color)

    # Save the image and log success or failure
    try:
        image.save(out_path, format="PNG")
        logger.info("✅ Screenshot saved at %s", out_path.resolve())
    except OSError as e:
        logger.exception("❌ Failed to save screenshot to %s: %s", out_path, e)
        raise

    return out_path


def safe_path_under(base: Path, target: Path) -> Path:
    """
    Ensure that `target` resides within the `base` directory.

    Args:
        base (Path): The allowed root directory.
        target (Path): The path to validate.

    Returns:
        Path: The resolved target path (absolute).

    Raises:
        ValueError: If `target` is outside of `base`.
    """
    base_resolved   = base.resolve()
    target_resolved = target.resolve()

    try:
        # This will raise ValueError if target_resolved is not under base_resolved
        target_resolved.relative_to(base_resolved)
    except ValueError:
        logger.error(
            "Path escape detected: %s is not under %s",
            target_resolved, base_resolved
        )
        raise ValueError(
            f"Security Error: '{target_resolved}' escapes allowed base '{base_resolved}'"
        )

    logger.debug("Validated safe path: %s", target_resolved)
    return target_resolved


def safe_write(path: Union[str, Path], content: str) -> None:
    """
    Safely write UTF-8 content to the specified file path.

    Features:
    - Prevents directory traversal attacks (no '..' in path).
    - Creates parent directories if they don't exist.
    - Writes atomically via a temporary file and rename to avoid partial writes.
    - Logs all operations and errors.

    Raises:
        SafeWriteError: On invalid path or write failure.
    """
    # Normalize path
    file_path = Path(path)

    # 1. Prevent directory traversal
    if any(part == '..' for part in file_path.parts):
        msg = f"Unsafe path detected: {file_path}"
        logger.error(msg)
        raise SafeWriteError(msg)

    try:
        # 2. Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # 3. Write atomically using NamedTemporaryFile in target directory
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False, dir=str(file_path.parent)) as tmp:
            tmp.write(content)
            temp_name = tmp.name

        # 4. Replace target file atomically
        Path(temp_name).replace(file_path)
        logger.info(f"✅ Successfully wrote to: {file_path}")
    except Exception as e:
        msg = f"Failed to write file {file_path}: {e}"
        logger.exception(msg)
        raise SafeWriteError(msg) from e
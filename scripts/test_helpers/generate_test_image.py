#!/usr/bin/env python3
"""
Generate a simple PNG test image containing the text "PayPal Login".
This can be used to validate OCR functionality.
"""

import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# announce script start
print("🔍 Running generate_test_image.py...")

def create_ocr_test_image(
    text: str = "PayPal Login",
    output_path: str = "tests/resources/test_ocr.png",
    font_path: str = "DejaVuSans-Bold.ttf",
    font_size: int = 36,
    padding: int = 20
) -> None:
    """
    Creates an image with the given text centered on a white background.

    - Ensures the output directory exists.
    - Attempts to load a TrueType font, falls back to default if unavailable.
    - Dynamically sizes the image to fit the text plus padding.
    """
    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Load font (fallback to default)
    try:
        font = ImageFont.truetype(font_path, font_size)
    except (IOError, OSError):
        font = ImageFont.load_default()

    # Measure text size using textbbox for accurate dimensions
    dummy_img = Image.new("RGB", (1, 1))
    draw_dummy = ImageDraw.Draw(dummy_img)
    bbox = draw_dummy.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    # Calculate image dimensions
    width = text_width + padding * 2
    height = text_height + padding * 2

    # Create white background image
    img = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(img)

    # Calculate position to center the text
    x = (width - text_width) // 2
    y = (height - text_height) // 2

    # Draw text in black
    draw.text((x, y), text, fill="black", font=font)

    # announce saving
    print("🖨 Saving image now...")
    img.save(output_path)
    print(f"✅ Test OCR image created at {output_path}")

if __name__ == "__main__":
    create_ocr_test_image()

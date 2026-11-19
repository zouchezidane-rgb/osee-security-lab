import os
import re
import shutil
from pathlib import Path

# 1. Configure your paths
# 1. Configure your paths (Adapte ces chemins selon ton PC)
OBSIDIAN_POSTS_DIR = Path(r"C:\Users\TonNom\Documents\MonCoffreObsidian\BlogPosts")
OBSIDIAN_ATTACHMENTS_DIR = Path(r"C:\Users\TonNom\Documents\MonCoffreObsidian\Attachments")
HUGO_CONTENT_DIR = Path(r"C:\HUGO\Blog\content\posts")
HUGO_IMAGES_DIR = Path(r"C:\HUGO\Blog\static\images")
# Ensure destination directories exist
HUGO_CONTENT_DIR.mkdir(parents=True, exist_ok=True)
HUGO_IMAGES_DIR.mkdir(parents=True, exist_ok=True)

# Regex to match ![[image.png]] or ![[image.png|alt text]]
WIKILINK_IMG_PATTERN = re.compile(r'!\[\[([^|\]]+\.(?:png|jpg|jpeg|gif|webp|svg))(?:\|([^\]]+))?\]\]', re.IGNORECASE)

def copy_image(image_name: str) -> str:
    """Finds the image in the Obsidian vault and copies it to Hugo's static folder."""
    # Look directly in attachments folder or search the vault if nested
    source_path = OBSIDIAN_ATTACHMENTS_DIR / image_name
    if not source_path.exists():
        matches = list(OBSIDIAN_ATTACHMENTS_DIR.rglob(image_name))
        if matches:
            source_path = matches[0]
        else:
            print(f"Warning: Image '{image_name}' not found.")
            return image_name

    # Replace spaces with hyphens for clean URLs
    clean_name = image_name.replace(" ", "-")
    dest_path = HUGO_IMAGES_DIR / clean_name
    shutil.copy2(source_path, dest_path)
    return clean_name

def process_markdown_file(md_path: Path):
    """Reads a markdown file, migrates its images, and saves it to Hugo."""
    content = md_path.read_text(encoding="utf-8")

    def replace_wikilink(match):
        raw_filename = match.group(1)
        alt_text = match.group(2) or Path(raw_filename).stem
        
        # Extract just the filename in case a relative path was used
        filename = Path(raw_filename).name
        clean_filename = copy_image(filename)
        
        # Hugo serves files in /static/images/ at /images/
        return f"![{alt_text}](/images/{clean_filename})"

    updated_content = WIKILINK_IMG_PATTERN.sub(replace_wikilink, content)
    
    dest_md_path = HUGO_CONTENT_DIR / md_path.name
    dest_md_path.write_text(updated_content, encoding="utf-8")
    print(f"Processed: {md_path.name}")

if __name__ == "__main__":
    for md_file in OBSIDIAN_POSTS_DIR.glob("*.md"):
        process_markdown_file(md_file)

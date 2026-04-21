# PhotoIQ — Claude Instructions

## Git Identity — MANDATORY
Before making ANY commit, run:
```bash
git config user.name "Rich Knowles"
git config user.email "rich@itwerks.net"
```
Every commit must show **Rich Knowles <rich@itwerks.net>**. No Co-Authored-By. No Claude attribution.

## What This Is
Web app for batch photo processing. Runs on a home network machine, accessed via browser.
Built for Laurie Ward — Higgins Family Collection.

## Stack
- Backend: Python + FastAPI (`backend/main.py`)
- Frontend: Vanilla HTML/CSS/JS (`frontend/`)
- Image processing: Pillow
- Start: `./start.sh` (sets up venv automatically)

## Watermark Spec
- File: `frontend/static/img/watermark.png`
- Text: © Laurie Ward – Sycamore, Illinois / Higgins Family Collection
- Opacity: 35% (default)
- Position: Bottom right
- Scale: 22% of image width (default)
- Angle: 0° straight or 345° angled

## Key Features
- Batch drag & drop upload
- Contact sheet (thumbnail grid)
- Multi-select with checkbox
- Per-photo rename + caption (written to EXIF)
- Watermark toggle + opacity/scale/angle controls
- Export selected or all → ZIP download
- Delete single or batch

## Aesthetic
Dark room. Amber/red safelight tones. Professional but warm.
Color vars in `frontend/static/css/app.css` — do not change the palette.

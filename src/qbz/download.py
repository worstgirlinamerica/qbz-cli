#!/usr/bin/env python3
import sys
import json
import os
import re
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from qbz.api import QobuzClient
from qbz.bundle import DEFAULT_APP_ID
from qbz.config import getboolean
from qbz.paths import configured_token_path, output_path
from qbz.quality import validate_response
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from mutagen.flac import FLAC, Picture
from mutagen.id3 import ID3, APIC, TXXX, USLT, TIT2, TPE1, TALB, TPE2, TRCK, TPOS, TCON, TDRC, TCOM, TCOP, TSRC, TPUB


console = Console()


def _segment_uuid(data):
    pos = 0
    while pos + 24 <= len(data):
        size = int.from_bytes(data[pos:pos + 4], "big")
        if size <= 0 or pos + size > len(data):
            break
        if data[pos + 4:pos + 8] == b"uuid":
            return data[pos + 8:pos + 24]
        pos += size
    return None


def _decrypt_segment(data, raw_key, segment_uuid):
    if segment_uuid is None:
        return bytes(data)
    buf = bytearray(data)
    pos = 0
    while pos + 8 <= len(buf):
        size = int.from_bytes(buf[pos:pos + 4], "big")
        if size <= 0 or pos + size > len(buf):
            break
        if buf[pos + 4:pos + 8] == b"uuid" and bytes(buf[pos + 8:pos + 24]) == segment_uuid:
            pointer = pos + 28
            data_end = pos + int.from_bytes(buf[pointer:pointer + 4], "big")
            pointer += 5
            frame_count = int.from_bytes(buf[pointer:pointer + 3], "big")
            pointer += 3
            for _ in range(frame_count):
                frame_len = int.from_bytes(buf[pointer:pointer + 4], "big")
                pointer += 6
                flags = int.from_bytes(buf[pointer:pointer + 2], "big")
                pointer += 2
                frame_start, data_end = data_end, data_end + frame_len
                if flags:
                    counter_len = buf[pos + 32]
                    counter = bytes(buf[pointer:pointer + counter_len]) + b"\x00" * (16 - counter_len)
                    decryptor = Cipher(algorithms.AES(raw_key), modes.CTR(counter)).decryptor()
                    buf[frame_start:data_end] = decryptor.update(bytes(buf[frame_start:data_end])) + decryptor.finalize()
                pointer += buf[pos + 32]
        pos += size
    return bytes(buf)


def download_segmented(track, output_path):
    """Download and decrypt a Qobuz web-player segmented stream."""
    if not track.get("url_template") or not track.get("raw_key"):
        raise RuntimeError("Qobuz returned an incomplete segmented stream descriptor")
    template = track["url_template"]
    last_segment = int(track["n_segments"])
    temp_path = str(output_path) + ".mp4"

    def fetch(number):
        response = requests.get(template.replace("$SEGMENT$", str(number)), timeout=30)
        response.raise_for_status()
        return response.content

    try:
        with Progress(
            TextColumn("[cyan]{task.description}"),
            BarColumn(bar_width=None, complete_style="bright_cyan", finished_style="bright_cyan", pulse_style="bright_cyan"),
            TaskProgressColumn(style="bright_white"),
            expand=True,
            transient=False,
        ) as progress:
            task = progress.add_task("Downloading", total=last_segment + 1)
            with open(temp_path, "wb") as stream:
                first = fetch(0)
                second = fetch(1)
                progress.advance(task, 2)
                segment_uuid = _segment_uuid(second)
                stream.write(_decrypt_segment(first, track["raw_key"], segment_uuid))
                stream.write(_decrypt_segment(second, track["raw_key"], segment_uuid))
                if last_segment >= 2:
                    with ThreadPoolExecutor(max_workers=8) as executor:
                        for data in executor.map(fetch, range(2, last_segment + 1)):
                            stream.write(_decrypt_segment(data, track["raw_key"], segment_uuid))
                            progress.advance(task)
        result = subprocess.run(
            ["ffmpeg", "-nostdin", "-v", "error", "-y", "-i", temp_path, "-c:a", "copy", "-f", "flac", str(output_path)],
            capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(f"ffmpeg could not assemble the segmented FLAC: {result.stderr[-500:]}")
    finally:
        try:
            Path(temp_path).unlink()
        except FileNotFoundError:
            pass

# Configuration
OUTPUT_ROOT = output_path()
OUTPUT_ROOT.mkdir(exist_ok=True)

def tqdm_download(url, output_path, title=None):
    """Download a file with a detailed Rich transfer display."""
    try:
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()

            total = int(r.headers.get("content-length", 0))
            with Progress(
                TextColumn("[cyan]{task.description}"),
                BarColumn(bar_width=None, complete_style="bright_cyan", finished_style="bright_cyan", pulse_style="bright_cyan"),
                TaskProgressColumn(style="bright_white"),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                expand=True,
                transient=False,
            ) as progress:
                task = progress.add_task("Downloading" if not title else f"Downloading {title}", total=total or None)
                with open(output_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            progress.advance(task, len(chunk))

    except requests.RequestException as e:
        raise RuntimeError(f"Download failed: {e}")

BLOCKED_EMBED_KEYS = {
    "id", "label_id", "upc", "performers_raw", "duration", "explicit",
    "maximum_bit_depth", "maximum_sampling_rate", "maximum_channel_count",
    "maximum_technical_specifications", "hires", "hires_streamable",
    "streamable", "downloadable", "artist_id", "album_id", "album_qobuz_id",
    "qobuz_url", "cover_url", "quality_id", "country", "album_download",
    "album_track_index", "album_track_count", "qobuz_raw", "qobuz_metadata",
    "credits", "credits_by_role", "credits_by_person", "release_dates",
}

ROLE_PRIORITY = [
    "Composer", "Lyricist", "Songwriter",
    "Producer", "Co-Producer", "Executive Producer", "Additional Producer",
    "Additional Production", "Vocal Producer", "Additional Studio Producer",
    "Associated Performer", "Featured Artist", "Vocals", "Background Vocal",
    "Choir", "Guitar", "Bass", "Drums", "Percussion", "Piano", "Keyboards",
    "Synthesizer", "Programming", "Programmer", "Strings", "Cello", "Violin",
    "Engineer", "Recording Engineer", "Vocal Engineer",
    "Additional Engineer", "Additional Vocal Recording Engineer",
    "Mixing Engineer", "Mixer", "Assistant Mixer", "Assistant Engineer",
    "Mastering Engineer", "A&R Administrator", "A&R Director", "Music Publisher",
]


def safe_path_part(value):
    text = str(value or "Unknown").strip()
    text = re.sub(r'[\\/:*?"<>|]+', "_", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    return text or "Unknown"

def first_nonempty(*values):
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None

def album_title_from_meta(meta):
    album = meta.get("album") if isinstance(meta, dict) else None
    if isinstance(album, str) and album.strip():
        return album.strip()
    if isinstance(album, dict):
        title = album.get("title")
        if title:
            return str(title)
    return first_nonempty(meta.get("album_title"), meta.get("title")) or "Unknown Album"

def artist_from_meta(meta):
    album = meta.get("album") if isinstance(meta, dict) else None
    if meta.get("album_artist"):
        return meta.get("album_artist")
    if isinstance(album, dict):
        artist = album.get("artist")
        if isinstance(artist, dict) and artist.get("name"):
            return artist.get("name")
        if isinstance(artist, str):
            return artist
    return first_nonempty(meta.get("artist"), meta.get("performer"), "Unknown Artist")

def year_from_meta(*metas):
    for meta in metas:
        if not isinstance(meta, dict):
            continue
        date = first_nonempty(meta.get("date"), meta.get("year"))
        if date:
            match = re.search(r"(19|20)\d{2}", str(date))
            if match:
                return match.group(0)
        release_dates = meta.get("release_dates")
        if isinstance(release_dates, dict):
            for value in release_dates.values():
                match = re.search(r"(19|20)\d{2}", str(value or ""))
                if match:
                    return match.group(0)
    return None

def explicit_from_meta(data, track=None):
    candidates = []
    if isinstance(data, dict):
        candidates.append(data.get("explicit"))
        candidates.append(data.get("parental_warning"))
        for item in data.get("tracks") or []:
            if isinstance(item, dict):
                candidates.append(item.get("explicit"))
                candidates.append(item.get("parental_warning"))
    if isinstance(track, dict):
        candidates.append(track.get("explicit"))
        candidates.append(track.get("parental_warning"))
    return any(value is True or str(value).strip().lower() in {"1", "true", "yes"} for value in candidates)

def bit_depth_from_meta(data, track=None):
    for meta in (track, data):
        if not isinstance(meta, dict):
            continue
        value = first_nonempty(meta.get("maximum_bit_depth"), meta.get("bit_depth"))
        if value not in (None, ""):
            try:
                return f"{int(float(value))}b"
            except (TypeError, ValueError):
                text = str(value).strip()
                if text:
                    return text if text.endswith("b") else f"{text}b"
    quality = str((track or {}).get("quality_id") or (data or {}).get("quality_id") or "")
    if quality == "5":
        return "MP3"
    return "16b"

def sample_rate_from_meta(data, track=None):
    for meta in (track, data):
        if not isinstance(meta, dict):
            continue
        value = first_nonempty(meta.get("maximum_sampling_rate"), meta.get("sampling_rate"), meta.get("sample_rate"))
        if value in (None, ""):
            specs = meta.get("maximum_technical_specifications")
            if specs:
                match = re.search(r"(\d+(?:\.\d+)?)\s*kHz", str(specs), re.I)
                if match:
                    value = match.group(1)
        if value not in (None, ""):
            try:
                number = float(value)
                if number >= 1000:
                    number = number / 1000
                if number.is_integer():
                    return f"{int(number)}k"
                return f"{number:g}k"
            except (TypeError, ValueError):
                text = str(value).strip().replace(" ", "")
                text = re.sub(r"(?i)khz$", "k", text)
                if text and not text.lower().endswith("k"):
                    text += "k"
                return text
    quality = str((track or {}).get("quality_id") or (data or {}).get("quality_id") or "")
    if quality == "5":
        return "44.1k"
    return None

def output_folder_for(data, track=None):
    base = data if isinstance(data, dict) else {}
    item = track or base
    album_batch = base.get("batch_type") == "album"

    artist = artist_from_meta(base) if album_batch else artist_from_meta(item)
    album_title = album_title_from_meta(base) if album_batch else album_title_from_meta(item)
    year = year_from_meta(base, item)
    quality = str(item.get("quality_id") or base.get("quality_id") or "")
    if quality == "5":
        quality_label = "MP3"
    else:
        bit_depth = bit_depth_from_meta(base, item)
        sample_rate = sample_rate_from_meta(base, item)
        quality_label = " ".join(part for part in (bit_depth, sample_rate) if part)
    explicit = explicit_from_meta(base, item)

    folder_name = f"{artist} - {album_title}"
    if year:
        folder_name += f" ({year})"
    if explicit:
        folder_name += " (E)"
    if quality_label:
        folder_name += f" [{quality_label}]"

    folder = OUTPUT_ROOT / safe_path_part(artist) / safe_path_part(folder_name)
    folder.mkdir(parents=True, exist_ok=True)
    return folder

def candidate_cover_base(meta):
    if not isinstance(meta, dict):
        return None
    image = meta.get("image") if isinstance(meta.get("image"), dict) else {}
    album = meta.get("album") if isinstance(meta.get("album"), dict) else {}
    album_image = album.get("image") if isinstance(album.get("image"), dict) else {}
    return first_nonempty(
        image.get("large"), image.get("medium"), image.get("small"),
        album_image.get("large"), album_image.get("medium"), album_image.get("small"),
        meta.get("cover_url"), album.get("cover_url"),
    )

def metadata_value(value):
    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)

def clean_person_name(name):
    text = str(name or "").strip()
    text = re.sub(r"\s+", " ", text)
    if not text:
        return None

    # Fix all-caps names from Qobuz credits without ruining short acronyms like FNZ.
    if text.isupper() and len(text) > 4:
        fixed = []
        for word in text.split(" "):
            bare = re.sub(r"[^A-Z0-9]", "", word)
            if bare in {"DJ", "OG", "FNZ", "MWA", "A&R"} or len(bare) <= 3:
                fixed.append(word)
            else:
                fixed.append(word[:1].upper() + word[1:].lower())
        text = " ".join(fixed)

    text = text.replace(" ,", ",").strip()
    return text

def unique_clean_values(values):
    if values in (None, "", [], {}):
        return []
    if not isinstance(values, (list, tuple, set)):
        values = [values]

    out = []
    seen = set()
    for value in values:
        text = clean_person_name(value)
        if not text:
            continue
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out

def comma_join(values):
    items = unique_clean_values(values)
    if not items:
        return None
    return ", ".join(items)

def dynamic_tag_name(role):
    raw = str(role or "").strip()
    compact = re.sub(r"[^a-z0-9]+", "", raw.casefold())

    canonical = {
        "aandradministrator": "A&R Administrator",
        "aradministrator": "A&R Administrator",
        "ardirector": "A&R Director",
        "additionalengineer": "Additional Engineer",
        "additionalproducer": "Additional Producer",
        "additionalproduction": "Additional Production",
        "additionalstudioproducer": "Additional Studio Producer",
        "additionalvocalrecordingengineer": "Additional Vocal Recording Engineer",
        "assistantengineer": "Assistant Engineer",
        "assistantmixer": "Assistant Mixer",
        "associatedperformer": "Associated Performer",
        "backgroundvocal": "Background Vocal",
        "backgroundvocals": "Background Vocal",
        "composer": "Composer",
        "composerlyricist": "ComposerLyricist",
        "coproducer": "Co-Producer",
        "engineer": "Engineer",
        "executiveproducer": "Executive Producer",
        "featuredartist": "Featured Artist",
        "lyricist": "Lyricist",
        "mainartist": "Main Artist",
        "masterer": "Mastering Engineer",
        "masteringengineer": "Mastering Engineer",
        "mixer": "Mixer",
        "mixingengineer": "Mixing Engineer",
        "musicpublisher": "Music Publisher",
        "producer": "Producer",
        "programmer": "Programmer",
        "programming": "Programming",
        "performingartist": "Performing Artist",
        "performingartists": "Performing Artists",
        "recordedby": "Recording Engineer",
        "recordingengineer": "Recording Engineer",
        "songwriter": "Songwriter",
        "vocalengineer": "Vocal Engineer",
        "vocalproducer": "Vocal Producer",
        "writer": "Songwriter",
    }
    if compact in canonical:
        return canonical[compact]

    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
    text = re.sub(r"[^A-Za-z0-9&]+", " ", text).strip()
    text = " ".join(word[:1].upper() + word[1:] for word in text.split())
    return text or "Credit"

def add_credit(credits, role, people):
    role_name = dynamic_tag_name(role)
    if role_name == "Main Artist":
        return

    # Qobuz sometimes combines ComposerLyricist into one role.
    roles = ["Composer", "Lyricist"] if role_name == "ComposerLyricist" else [role_name]

    for final_role in roles:
        credits.setdefault(final_role, [])
        if isinstance(people, list):
            credits[final_role].extend(people)
        else:
            credits[final_role].append(people)

def parse_performers_raw(raw):
    credits = {}
    if not raw:
        return credits

    # Qobuz credit format: "Name, Role, Role - Name, Role"
    chunks = [chunk.strip() for chunk in str(raw).split(" - ") if chunk.strip()]
    suffixes = {"Jr", "Jr.", "Sr", "Sr.", "II", "III", "IV", "V"}

    for chunk in chunks:
        parts = [part.strip() for part in chunk.split(",") if part.strip()]
        if not parts:
            continue

        name = parts[0]
        roles = parts[1:]

        # Repair names like "Melvin Godfrey, Jr, Additional Vocal Recording Engineer"
        if roles and roles[0] in suffixes:
            name = f"{name}, {roles[0]}"
            roles = roles[1:]

        if not roles:
            continue

        for role in roles:
            add_credit(credits, role, name)

    return credits

def build_credit_tags(meta):
    credit_tags = {}

    if isinstance(meta.get("credits_by_role"), dict):
        for role, people in meta["credits_by_role"].items():
            add_credit(credit_tags, role, people)

    for role, people in parse_performers_raw(meta.get("performers_raw")).items():
        add_credit(credit_tags, role, people)

    # Fallbacks from normalized metadata.
    if meta.get("producers"):
        add_credit(credit_tags, "Producer", meta.get("producers"))
    if meta.get("lyricists"):
        add_credit(credit_tags, "Lyricist", meta.get("lyricists"))

    # Composer is written as a core field, but if ComposerLyricist is the only source,
    # this also makes Lyricist cleanly appear.
    if meta.get("composers"):
        add_credit(credit_tags, "Composer", meta.get("composers"))

    ordered = {}
    for role in ROLE_PRIORITY:
        if role in credit_tags:
            joined = comma_join(credit_tags.pop(role))
            if joined:
                ordered[role] = joined

    for role in sorted(credit_tags):
        joined = comma_join(credit_tags[role])
        if joined:
            ordered[role] = joined

    return ordered

def qobuz_cover_candidates(meta, sizes):
    """Mirror qobuz-dl cover handling: take Qobuz *_600.jpg and rewrite the size suffix."""
    base = candidate_cover_base(meta)
    if not base:
        return []

    out = []
    for size in sizes:
        if size:
            out.append(re.sub(r"_(\d+|org|max)\.jpg$", f"_{size}.jpg", base))
    out.append(base)

    seen = set()
    clean = []
    for url in out:
        if url and url not in seen:
            seen.add(url)
            clean.append(url)
    return clean

def download_cover_to(path, meta, sizes):
    for url in qobuz_cover_candidates(meta, sizes):
        try:
            r = requests.get(url, timeout=30, headers={"User-Agent": "authorized-fetch-tool/1.0"})
            if r.status_code >= 400:
                continue
            data = r.content or b""
            content_type = r.headers.get("content-type", "").lower()
            if "image" not in content_type and not data.startswith(b"\xff\xd8"):
                continue
            if not data.startswith(b"\xff\xd8"):
                continue
            path.write_bytes(data)
            console.print(f"[bright_cyan]✓ Artwork downloaded[/bright_cyan] [dim]{url}[/dim]")
            return path, url
        except requests.RequestException:
            continue
    return None, None

def prepare_covers(folder, *metas):
    """Save one original/highest-quality cover.jpg and use that same file for embedding."""
    folder.mkdir(parents=True, exist_ok=True)
    cover_path = folder / "cover.jpg"

    # Clean up older/temp embedded-cover files from previous versions.
    for temp_name in ("embed_cover.jpg", "embed_cover.jpeg", "cover.jpeg"):
        temp_path = folder / temp_name
        if temp_path != cover_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

    usable_meta = [m for m in metas if isinstance(m, dict)]

    saved = cover_path if cover_path.exists() and cover_path.read_bytes().startswith(b"\xff\xd8") else None
    if not saved:
        for meta in usable_meta:
            saved, url = download_cover_to(cover_path, meta, ("org", "max", "2000", "1500", "1200", "1000", "800", "600"))
            if saved:
                break

    return saved, saved
def clear_existing_art(audio):
    try:
        audio.clear_pictures()
    except Exception:
        pass

def embed_flac_cover(audio, cover_path):
    if not cover_path or not cover_path.exists():
        return
    data = cover_path.read_bytes()
    if not data.startswith(b"\xff\xd8"):
        return

    clear_existing_art(audio)
    image = Picture()
    image.type = 3
    image.mime = "image/jpeg"
    image.desc = "Cover"
    image.data = data
    audio.add_picture(image)
    console.print("[bright_cyan]✓ Artwork embedded in FLAC[/bright_cyan]")

def write_flac_tag(audio, key, value):
    if value in (None, "", [], {}):
        return
    if isinstance(value, list):
        value = comma_join(value)
    else:
        value = metadata_value(value)
    if value not in (None, ""):
        audio[key] = value

def tag_file(file_path, meta, ext, cover_path):
    """
    Clean metadata writer:
    - no raw JSON/API passthrough tags
    - comma-separated, ordered credits
    - dynamic roles preserved
    - verified JPEG cover embedding
    """
    try:
        if ext == "flac":
            audio = FLAC(file_path)
            audio.clear()

            core_tags = {
                "title": meta.get("title"),
                "artist": meta.get("artist") or meta.get("performer"),
                "album": meta.get("album") if isinstance(meta.get("album"), str) else meta.get("album_title"),
                "albumartist": meta.get("album_artist"),
                "tracknumber": meta.get("track_number"),
                "tracktotal": meta.get("track_total"),
                "discnumber": meta.get("disc_number"),
                "disctotal": meta.get("disc_total"),
                "date": meta.get("date") or meta.get("year"),
                "genre": meta.get("genre"),
                "label": meta.get("label"),
                "isrc": meta.get("isrc"),
                "barcode": meta.get("barcode") or meta.get("upc"),
                "copyright": meta.get("copyright"),
                "lyrics": meta.get("lyrics"),
            }

            composers = meta.get("composers") or meta.get("composer")
            if composers:
                core_tags["composer"] = composers

            lyricists = meta.get("lyricists")
            if lyricists:
                core_tags["lyricist"] = lyricists

            for key, value in core_tags.items():
                write_flac_tag(audio, key, value)

            for key, value in build_credit_tags(meta).items():
                # Avoid Composer double-writing if already present as core tag.
                if key == "Composer" and composers:
                    continue
                write_flac_tag(audio, key, value)

            # Optional explicit flag, cleanly only.
            if meta.get("explicit") is not None:
                write_flac_tag(audio, "explicit", meta.get("explicit"))

            embed_flac_cover(audio, cover_path)
            audio.save()

        elif ext == "mp3":
            audio = ID3(file_path)

            def set_frame(frame_id, frame):
                audio.delall(frame_id)
                audio.add(frame)

            title = metadata_value(meta.get("title"))
            artist = metadata_value(meta.get("artist") or meta.get("performer"))
            album = metadata_value(meta.get("album") if isinstance(meta.get("album"), str) else meta.get("album_title"))
            albumartist = metadata_value(meta.get("album_artist"))
            track = metadata_value(meta.get("track_number"))
            total = metadata_value(meta.get("track_total"))
            disc = metadata_value(meta.get("disc_number"))
            disc_total = metadata_value(meta.get("disc_total"))
            genre = metadata_value(meta.get("genre"))
            date = metadata_value(meta.get("date") or meta.get("year"))
            composer = comma_join(meta.get("composers")) or metadata_value(meta.get("composer"))
            copyright_text = metadata_value(meta.get("copyright"))
            isrc = metadata_value(meta.get("isrc"))
            label = metadata_value(meta.get("label"))
            barcode = metadata_value(meta.get("barcode") or meta.get("upc"))

            if title: set_frame("TIT2", TIT2(encoding=3, text=title))
            if artist: set_frame("TPE1", TPE1(encoding=3, text=artist))
            if album: set_frame("TALB", TALB(encoding=3, text=album))
            if albumartist: set_frame("TPE2", TPE2(encoding=3, text=albumartist))
            if track: set_frame("TRCK", TRCK(encoding=3, text=f"{track}/{total}" if total else track))
            if disc: set_frame("TPOS", TPOS(encoding=3, text=f"{disc}/{disc_total}" if disc_total else disc))
            if genre: set_frame("TCON", TCON(encoding=3, text=genre))
            if date: set_frame("TDRC", TDRC(encoding=3, text=date))
            if composer: set_frame("TCOM", TCOM(encoding=3, text=composer))
            if copyright_text: set_frame("TCOP", TCOP(encoding=3, text=copyright_text))
            if isrc: set_frame("TSRC", TSRC(encoding=3, text=isrc))
            if label: set_frame("TPUB", TPUB(encoding=3, text=label))
            lyrics = metadata_value(meta.get("lyrics"))
            if lyrics:
                audio.delall("USLT")
                audio.add(USLT(encoding=3, lang="eng", desc="", text=lyrics))

            # Remove old custom frames from bad passthrough runs.
            for old in list(audio.getall("TXXX")):
                if old.desc in BLOCKED_EMBED_KEYS or old.desc.lower() in BLOCKED_EMBED_KEYS:
                    audio.delall(f"TXXX:{old.desc}")

            if barcode:
                audio.delall("TXXX:barcode")
                audio.delall("TXXX:BARCODE")
                audio.add(TXXX(encoding=3, desc="barcode", text=barcode))

            for key, value in build_credit_tags(meta).items():
                if key == "Composer" and composer:
                    continue
                audio.delall(f"TXXX:{key}")
                audio.add(TXXX(encoding=3, desc=key, text=value))

            if cover_path and cover_path.exists():
                data = cover_path.read_bytes()
                if data.startswith(b"\xff\xd8"):
                    audio.delall("APIC")
                    audio.add(APIC(encoding=3, mime="image/jpeg", type=3, desc="Cover", data=data))
                    console.print("[bright_cyan]✓ Artwork embedded in MP3[/bright_cyan]")

            audio.save()

    except Exception as e:
        print(f"Tagging Error: {e}")


def complete_audio(path, expected_duration):
    """Return true only for a playable file matching the track duration."""
    if not path.is_file() or path.stat().st_size < 4096:
        return False
    if path.suffix.lower() == ".flac" and path.read_bytes()[:4] != b"fLaC":
        return False
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=nw=1:nk=1", str(path)],
            capture_output=True, text=True, check=True,
        )
        actual = float(result.stdout.strip())
        expected = float(expected_duration or 0)
        return expected <= 0 or abs(actual - expected) <= 2.0
    except (OSError, ValueError, subprocess.CalledProcessError):
        return False


def write_credit_sheet(data, tracks):
    if not data.get("write_credits"):
        return
    batch_album = data.get("album") if data.get("batch_type") == "album" else None
    first = tracks[0] if tracks else data
    album = batch_album or (first.get("album") if isinstance(first.get("album"), dict) else {})
    artist = (album.get("artist") if isinstance(album, dict) else None) or first.get("album_artist") or first.get("artist") or "Unknown Artist"
    if isinstance(artist, dict):
        artist = artist.get("name") or "Unknown Artist"
    title = (album.get("title") if isinstance(album, dict) else None) or first.get("album") or first.get("title") or "Unknown Album"
    sheet = OUTPUT_ROOT / safe_path_part(f"{artist} - {title} - Credits.txt")
    lines = [f"{artist} - {title}", "=" * (len(str(artist)) + len(str(title)) + 3), ""]
    for track in tracks:
        lines.append(f"{track.get('track_number') or ''}. {track.get('title') or 'Untitled'}")
        roles = track.get("credits_by_role") or {}
        for role in sorted(roles, key=lambda value: dynamic_tag_name(value).casefold()):
            people = roles[role]
            people = comma_join(people if isinstance(people, list) else [people]) or ""
            lines.append(f"  {dynamic_tag_name(role)}: {people}")
        lines.append("")
    sheet.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    if getboolean("display", "show_paths", True):
        print(f"Credits saved: {sheet}")

def main(metadata_path):
    # Setup Auth
    token = ""
    token_file = configured_token_path()

    if token_file.is_file():
        token = token_file.read_text(encoding="utf-8").strip()

    if not token:
        token = os.getenv("QOBUZ_TOKEN", "").strip()

    if not token:
        raise RuntimeError("No Qobuz auth token available")

    client = QobuzClient(
        app_id=os.getenv("QOBUZ_APP_ID") or DEFAULT_APP_ID,
        token=token,
    )

    with open(metadata_path, 'r') as f:
        data = json.load(f)

    # Detect Album/Batch vs Single
    is_batch = data.get("batch_type") == "album"
    tracks = data.get("tracks") if is_batch else [data]
    write_credit_sheet(data, tracks)

    # 1. Process Tracks into ~/Qobuz/Artist/Album or Single Title
    for track in tracks:
        quality_id = track.get("quality_id", data.get("quality_id", "27"))
        track_id = track.get("id")
        ext = "mp3" if str(quality_id) == "5" else "flac"

        # Use only the quality the user selected. Never silently downgrade a
        # 27/7/6 request to another format; report the failure instead.
        requested = str(quality_id)
        qualities = [requested]
        seen = set()
        downloaded = False
        last_error = None
        for candidate in qualities:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                track_url = client.get_track_url(track_id, candidate)
                url = track_url.get("url")
                returned_format = str(track_url.get("format_id") or candidate)
                highest_available_response = candidate == "27" and returned_format in {"6", "7", "27"}
                if returned_format != candidate and not highest_available_response:
                    raise RuntimeError(
                        f"Qobuz returned format {returned_format} for requested format {candidate}"
                    )
                validate_response(candidate, track_url, data, track)

                # Qobuz's catalog maximum is only a prediction. The stream
                # response is authoritative, so use it for the folder name
                # and embedded metadata labels.
                download_track = dict(track)
                actual_bits = first_nonempty(track_url.get("bit_depth"), track_url.get("bits_depth"))
                actual_rate = first_nonempty(track_url.get("sampling_rate"), track_url.get("sample_rate"))
                if actual_bits not in (None, ""):
                    download_track["bit_depth"] = actual_bits
                if actual_rate not in (None, ""):
                    download_track["sampling_rate"] = actual_rate

                folder = output_folder_for(data, download_track)
                _, embed_cover_path = prepare_covers(
                    folder, data, download_track,
                    download_track.get("album") if isinstance(download_track.get("album"), dict) else {},
                )

                # Consistent Filename format
                num = download_track.get('track_number', 0)
                title = safe_path_part(download_track.get('title', 'Unknown'))
                filename = f"{int(num):02d}. {title}.{ext}" if str(num).isdigit() and int(num) else f"{title}.{ext}"
                safe_path = folder / filename

                if complete_audio(safe_path, download_track.get("duration")):
                    print(f"Already complete: {safe_path}")
                    downloaded = True
                    break

                if track_url.get("url_template"):
                    download_segmented(track_url, safe_path)
                    downloaded = True
                    break
                if not url or track_url.get("sample"):
                    raise RuntimeError("Qobuz returned a preview or no URL")
                tqdm_download(url, str(safe_path), title)
                if candidate != "5" and not safe_path.read_bytes().startswith(b"fLaC"):
                    raise RuntimeError("Qobuz returned non-FLAC bytes")
                downloaded = True
                break
            except Exception as exc:
                last_error = exc
                try:
                    safe_path.unlink()
                except FileNotFoundError:
                    pass
        if not downloaded:
            raise RuntimeError(f"No complete authorized stream returned: {last_error}")

        # 3. Tag
        tag_file(safe_path, download_track, ext, embed_cover_path)
        if getboolean("display", "show_paths", True):
            print(f"Saved: {safe_path}")

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except KeyboardInterrupt:
        print("\nAlbum download interrupted. Completed tracks are safe; rerun to resume.")
        raise SystemExit(130)

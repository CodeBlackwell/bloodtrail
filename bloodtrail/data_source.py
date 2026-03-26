"""
Data Source Abstraction for BloodHound Data

Provides a unified interface for reading BloodHound JSON files from either:
- A directory of JSON files
- A ZIP archive containing JSON files (SharpHound output)

This allows bloodtrail to directly process SharpHound ZIP output without
manual extraction.
"""

import json
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Tuple, Optional, List
from io import TextIOWrapper


class DataSource(ABC):
    """Abstract base class for BloodHound data sources"""

    @abstractmethod
    def list_json_files(self) -> List[str]:
        """Return list of JSON filenames available in the source"""
        pass

    @abstractmethod
    def read_json(self, filename: str) -> dict:
        """Read and parse a JSON file from the source"""
        pass

    @abstractmethod
    def iter_json_files(self) -> Iterator[Tuple[str, dict]]:
        """Iterate over all JSON files, yielding (filename, parsed_data) tuples"""
        pass

    @property
    @abstractmethod
    def source_path(self) -> Path:
        """Return the path to the data source"""
        pass

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Return 'directory' or 'zip'"""
        pass


class DirectoryDataSource(DataSource):
    """Data source for a directory of JSON files"""

    def __init__(self, directory: Path):
        self._path = Path(directory)
        if not self._path.exists():
            raise FileNotFoundError(f"Directory not found: {self._path}")
        if not self._path.is_dir():
            raise ValueError(f"Not a directory: {self._path}")

    def _parse_json_with_fallback(self, json_path: Path) -> dict:
        """Parse JSON with encoding fallbacks for Windows/Linux compatibility"""
        encodings = ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']
        last_error = None

        for encoding in encodings:
            try:
                with open(json_path, encoding=encoding) as f:
                    return json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                last_error = e
                continue

        raise last_error or ValueError(f"Could not parse {json_path}")

    def list_json_files(self) -> List[str]:
        return [f.name for f in self._path.glob("*.json")]

    def read_json(self, filename: str) -> dict:
        json_path = self._path / filename
        return self._parse_json_with_fallback(json_path)

    def iter_json_files(self) -> Iterator[Tuple[str, dict]]:
        for json_path in self._path.glob("*.json"):
            try:
                data = self._parse_json_with_fallback(json_path)
                yield (json_path.name, data)
            except json.JSONDecodeError as e:
                print(f"[!] JSON parse error in {json_path.name}: {e}")
            except Exception as e:
                print(f"[!] Error reading {json_path.name}: {e}")

    @property
    def source_path(self) -> Path:
        return self._path

    @property
    def source_type(self) -> str:
        return "directory"


class ZipDataSource(DataSource):
    """Data source for a ZIP archive containing JSON files"""

    def __init__(self, zip_path: Path):
        self._path = Path(zip_path)
        if not self._path.exists():
            raise FileNotFoundError(f"ZIP file not found: {self._path}")
        if not zipfile.is_zipfile(self._path):
            raise ValueError(f"Not a valid ZIP file: {self._path}")

        self._zipfile: Optional[zipfile.ZipFile] = None

    def _get_zip(self) -> zipfile.ZipFile:
        """Lazily open the ZIP file"""
        if self._zipfile is None:
            self._zipfile = zipfile.ZipFile(self._path, 'r')
        return self._zipfile

    def list_json_files(self) -> List[str]:
        zf = self._get_zip()
        json_files = []
        for name in zf.namelist():
            # Handle nested directories in ZIP
            basename = Path(name).name
            if basename.lower().endswith('.json') and not name.startswith('__MACOSX'):
                json_files.append(basename)
        return json_files

    def _find_json_in_zip(self, filename: str) -> Optional[str]:
        """Find a JSON file in the ZIP, handling nested paths"""
        zf = self._get_zip()
        filename_lower = filename.lower()

        for name in zf.namelist():
            basename = Path(name).name
            if basename.lower() == filename_lower and not name.startswith('__MACOSX'):
                return name
        return None

    def _parse_json_with_fallback(self, zf: zipfile.ZipFile, zip_path: str) -> dict:
        """Parse JSON with encoding fallbacks for Windows/Linux compatibility"""
        # Try encodings in order: utf-8-sig (handles BOM), utf-8, latin-1 (fallback)
        encodings = ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']
        last_error = None

        for encoding in encodings:
            try:
                with zf.open(zip_path) as f:
                    text_wrapper = TextIOWrapper(f, encoding=encoding)
                    return json.load(text_wrapper)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                last_error = e
                continue

        raise last_error or ValueError(f"Could not parse {zip_path}")

    def read_json(self, filename: str) -> dict:
        zf = self._get_zip()
        zip_path = self._find_json_in_zip(filename)

        if zip_path is None:
            raise FileNotFoundError(f"JSON file not found in ZIP: {filename}")

        return self._parse_json_with_fallback(zf, zip_path)

    def iter_json_files(self) -> Iterator[Tuple[str, dict]]:
        zf = self._get_zip()

        for name in zf.namelist():
            # Skip macOS metadata and non-JSON files
            if name.startswith('__MACOSX'):
                continue

            basename = Path(name).name
            if not basename.lower().endswith('.json'):
                continue

            try:
                data = self._parse_json_with_fallback(zf, name)
                yield (basename, data)
            except json.JSONDecodeError as e:
                print(f"[!] JSON parse error in {basename}: {e}")
            except Exception as e:
                print(f"[!] Error reading {basename} from ZIP: {e}")

    @property
    def source_path(self) -> Path:
        return self._path

    @property
    def source_type(self) -> str:
        return "zip"

    def close(self):
        """Close the ZIP file"""
        if self._zipfile is not None:
            self._zipfile.close()
            self._zipfile = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def create_data_source(path: Path) -> DataSource:
    """
    Factory function to create the appropriate DataSource.

    Args:
        path: Path to either a directory or ZIP file

    Returns:
        DirectoryDataSource or ZipDataSource

    Raises:
        FileNotFoundError: If path doesn't exist
        ValueError: If path is neither a directory nor a valid ZIP
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_dir():
        return DirectoryDataSource(path)

    if path.suffix.lower() == '.zip' or zipfile.is_zipfile(path):
        return ZipDataSource(path)

    raise ValueError(f"Path must be a directory or ZIP file: {path}")


def is_valid_bloodhound_source(path: Path) -> Tuple[bool, str]:
    """
    Validate that a path is a valid BloodHound data source.

    Args:
        path: Path to validate

    Returns:
        Tuple of (is_valid, message)
    """
    path = Path(path)

    if not path.exists():
        return (False, f"Path not found: {path}")

    try:
        source = create_data_source(path)
        json_files = source.list_json_files()

        if not json_files:
            return (False, f"No JSON files found in: {path}")

        # Close if it's a ZIP source
        if hasattr(source, 'close'):
            source.close()

        return (True, f"Found {len(json_files)} JSON files ({source.source_type})")

    except Exception as e:
        return (False, str(e))

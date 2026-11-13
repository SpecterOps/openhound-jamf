"""Build a Community extension bundle from JSON data without collector dependencies.

Inputs below --extension (default: extension/):
    schema.json: required Community schema.
    saved_queries.json (queries wrapper) OR saved_searches/**/*.json: queries.
    pz_rules.json (pz_rules wrapper) OR privilege_zone_rules/**/*.json: rules.
Each individual file contains one record. Competing layouts for either component
are rejected. Records must include stable query_key/key values. Individual rules
may use legacy zone/cypher fields; only Tier Zero rules can be converted to seeds.

Output under the required --output directory:
    <schema.name>-v<schema.version without a leading v>.zip
The ZIP contains schema.json and any supplied nonempty component sets at its root.
JSON ordering and ZIP metadata are fixed so the same inputs produce identical bytes. The script prints the resulting filename.
Invalid inputs exit with status 1.

Format: https://bloodhound.specterops.io/opengraph/developer/extension-bundles
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any
from zipfile import ZIP_STORED, ZipFile, ZipInfo

MAX_BYTES = 10 * 1024 * 1024


def require(condition: object, message: str) -> None:
    """Raise ValueError with message when condition is false."""
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Return a JSON object from pairs, raising ValueError for duplicate fields."""
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(path: Path, root: Path) -> Any:
    """Read JSON from path below root, rejecting unsafe paths and malformed data.

    Raises:
        ValueError: Unsafe paths, excessive size, duplicate fields or invalid JSON.
        OSError: The input cannot be read.
    """
    require(not any(p.is_symlink() for p in [path, *path.parents]),
            f"Symlink input: {path}")
    require(path.resolve().is_relative_to(root.resolve()), f"Input escapes extension: {path}")
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, f"Invalid input size: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, f"Invalid JSON number: {value}"))


def require_text(record: dict[str, Any], field: str) -> None:
    """Raise ValueError unless record[field] is a nonblank string."""
    require(isinstance(record.get(field), str) and record[field].strip(),
            f"Missing or invalid {field}")


def load_component_records(root: Path, filename: str, directory: str, wrapper: str) -> list[Any]:
    """Load one component layout beneath root; return [] when neither is present.

    filename is a consolidated wrapper file; directory contains individual JSON
    records. Raises ValueError for competing layouts or unsafe/oversized inputs,
    and OSError when reading fails. Record validation is performed by the caller.
    """
    consolidated = root / filename
    individual = root / directory
    require(not individual.is_symlink(), f"Symlink directory: {individual}")
    require(not individual.exists() or individual.is_dir(), f"Not a directory: {individual}")
    if individual.exists():
        require(not any(path.is_symlink() for path in individual.rglob("*")),
                f"Symlink inside {individual}")
    files = sorted(individual.rglob("*.json")) if individual.exists() else []
    require(len(files) <= 1000, "Too many component inputs")
    require(sum(path.stat().st_size for path in files) <= MAX_BYTES,
            "Combined component inputs exceed 10 MiB")
    require(not (consolidated.exists() and files),
            f"Use either {filename} or {directory}, not both")
    if consolidated.exists() or consolidated.is_symlink():
        data = read_json(consolidated, root)
        require(isinstance(data, dict) and set(data) == {wrapper}, f"Expected {wrapper} wrapper")
        records = data[wrapper]
        require(isinstance(records, list) and records, f"Empty or invalid {filename}")
    else:
        records = [read_json(path, root) for path in files]
    return records


def validate_query(record: dict[str, Any]) -> None:
    """Validate query-specific fields in record, raising ValueError on failure."""
    require_text(record, "query")
    allowed = {"query_key", "name", "description", "query", "category"}
    require(not set(record) - allowed, f"Unknown component fields: {set(record) - allowed}")


def normalize_rule(record: dict[str, Any]) -> None:
    """Convert legacy Tier Zero fields in place and validate the rule's seed/flags.

    Raises ValueError for custom zones, mixed formats or invalid rule fields.
    Existing stable keys and explicit false flag values are preserved.
    """
    if "cypher" in record or "zone" in record:
        require("seeds" not in record and record.get("zone") == "Tier Zero",
                "Only Tier Zero legacy rules can be bundled; mixed formats are invalid")
        require_text(record, "cypher")
        record["seeds"] = [{"type": 2, "value": record.pop("cypher")}]
        record.pop("zone")
    seeds = record.get("seeds")
    require(isinstance(seeds, list) and len(seeds) == 1, "Rules need exactly one seed")
    seed = seeds[0]
    require(isinstance(seed, dict) and set(seed) == {"type", "value"}
            and type(seed["type"]) is int and seed["type"] == 2, "Invalid Cypher seed")
    require_text(seed, "value")
    for field in ["enabled", "allow_disable"]:
        require(type(record.get(field, True)) is bool, f"Invalid {field}")
    allowed = {"key", "name", "description", "enabled", "allow_disable", "seeds"}
    require(not set(record) - allowed, f"Unknown component fields: {set(record) - allowed}")


def component(root: Path, filename: str, directory: str, wrapper: str,
              key: str) -> dict[str, list[dict[str, Any]]] | None:
    """Return validated records sorted by stable key, or None for an absent set.

    root, filename, directory and wrapper select the input layout; key names the
    stable identifier field. Invalid records or duplicate keys/names raise
    ValueError; input-read failures raise OSError.
    """
    records = load_component_records(root, filename, directory, wrapper)
    keys, names, converted = set(), set(), []
    for record in records:
        require(isinstance(record, dict), "Component records must be objects")
        record = dict(record)
        if wrapper == "queries":
            validate_query(record)
        else:
            normalize_rule(record)
        require_text(record, key)
        require_text(record, "name")
        for field in ["description", "category"]:
            require(field not in record or isinstance(record[field], str), f"Invalid {field}")
        require(record[key] not in keys and record["name"] not in names, "Duplicate component key or name")
        keys.add(record[key])
        names.add(record["name"])
        converted.append(record)
    return {wrapper: sorted(converted, key=lambda record: record[key])} if converted else None


def encoded(data: Any) -> bytes:
    """Serialize data as deterministic UTF-8 JSON; reject values above 10 MiB."""
    value = (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(value) <= MAX_BYTES, "Component exceeds 10 MiB")
    return value


def build(root: Path, output: Path) -> Path:
    """Build and verify a Community ZIP from root into output; return its path.

    Raises:
        ValueError: Input or generated bundle validation fails.
        OSError: Inputs cannot be read or the output cannot be written.
    """
    schema = read_json(root / "schema.json", root)
    require(isinstance(schema, dict) and isinstance(schema.get("schema"), dict), "Missing schema metadata")
    metadata = schema["schema"]
    for field in ["name", "version", "namespace"]:
        require_text(metadata, field)
    # Restrict the schema name to a safe single filename component.
    require(re.fullmatch(r"[A-Za-z0-9_-]+", metadata["name"]), "Unsafe schema name")
    version = metadata["version"].removeprefix("v")
    # Match major.minor.patch, with optional prerelease and build suffixes.
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version),
            "Invalid schema version")
    require(not {"queries", "pz_rules"} & set(schema), "Components cannot be embedded in schema")
    for field in ["node_kinds", "relationship_kinds"]:
        require(isinstance(schema.get(field), list), f"Missing {field}")
    require("relationship_findings" not in schema or schema["relationship_findings"] == [],
            "Community bundles cannot contain findings")
    parts = {"schema.json": encoded(schema)}
    for filename, directory, wrapper, key in [
        ("saved_queries.json", "saved_searches", "queries", "query_key"),
        ("pz_rules.json", "privilege_zone_rules", "pz_rules", "key"),
    ]:
        data = component(root, filename, directory, wrapper, key)
        if data is not None:
            parts[filename] = encoded(data)
    require("relationship_findings" not in schema or "pz_rules.json" in parts,
            "A findings section requires PZ rules")
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{metadata['name']}-v{version}.zip"
    with ZipFile(target, "w", compression=ZIP_STORED) as archive:
        for name, value in sorted(parts.items()):
            # ZIP timestamps cannot predate 1980. Fix the earliest supported date
            # so wall-clock time does not change the output between builds.
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3  # ZIP host-system code for Unix.
            # Store the Unix regular-file type and 0644 permissions in the high word.
            info.external_attr = 0o100644 << 16
            archive.writestr(info, value)
    with ZipFile(target) as archive:
        require(archive.namelist() == sorted(parts) and archive.testzip() is None, "Invalid ZIP")
        for name, value in parts.items():
            require(archive.read(name) == value, f"ZIP content mismatch: {name}")
    print(target.name)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", type=Path, default=Path("extension"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.extension, args.output)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Bundle error: {error}\n")

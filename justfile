set dotenv-load := true

collect +args='jamf /tmp/output/raw/':
    @echo "Collecting data"
    uv run src/main.py collect {{args}}

preprocess +args='jamf /tmp/output/raw/jamf':
    @echo "Preprocessing data"
    uv run openhound preprocess {{args}}

convert +args='jamf /tmp/output/raw/jamf /tmp/output/graph/jamf':
    @echo "Converting data"
    uv run openhound convert {{args}}

sync:
    @echo "Syncing dependencies"
    uv sync --group dev

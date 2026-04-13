set dotenv-load := true

collect +args:
    @echo "Collecting data"
    uv run src/main.py collect jamf {{args}}

preprocess +args:
    @echo "Collecting data"
    uv run src/main.py preprocess jamf {{args}}

convert +args:
    @echo "Converting data"
    uv run src/main.py convert jamf {{args}}

sync:
    @echo "Syncing dependencies"
    uv sync --group dev

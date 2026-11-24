"""Private task entrypoint; receives a job descriptor, not command text."""
import json
from pathlib import Path
import sys
import traceback
from ctfhub.operations import run

if __name__ == '__main__':
    try:
        job = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
        run(job['operation'], job['values'], Path(sys.argv[1]).parent)
    except Exception as error:
        print(f'执行失败：{error}', flush=True)
        sys.exit(1)

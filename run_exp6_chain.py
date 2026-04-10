import sys
sys.stdout = open('/tmp/exp6_run.log', 'w', buffering=1)
sys.stderr = sys.stdout
from experiments.exp6_correctness import run_all
run_all(use_chain=True)
print('=== EXP6 DONE ===')

import sys
sys.stdout = open('/tmp/exp5_run.log', 'w', buffering=1)
sys.stderr = sys.stdout
from experiments.exp5_update_revoke import run_all
run_all(use_chain=True)
print('=== EXP5 DONE ===')

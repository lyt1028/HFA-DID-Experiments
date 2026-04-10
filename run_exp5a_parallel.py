import sys, os
sys.path.insert(0, os.path.expanduser("~/HFA-DID-Experiments"))
os.chdir(os.path.expanduser("~/HFA-DID-Experiments"))
from experiments.exp5_update_revoke import run_exp5a_single_operation
results = run_exp5a_single_operation(
    committee_sizes=(4, 6, 8, 10),
    num_trials=30,
    ch_bits=128,
    use_chain=True,
    parallel_bls=True,
)
print("\n=== DONE ===")
for r in results:
    print(r)

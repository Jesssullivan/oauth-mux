"""Explicit factor-free Secret Service setup actions; resident custody is separate."""
import json
import os
from pathlib import Path
import subprocess
import sys
import resident_vault as common
vault=common.vault
resident=common.resident
require=common.require
deadline=common.deadline
budget=common.budget
private_manifest=common.private_manifest
retain=common.retain
PHASE="arguments"
CLIENT_STATUSES=frozenset(("arguments","deadline","bus-unavailable","identity-refused","collection-refused",
    "unlock-refused","collection-input-refused","prompt-unavailable","cancelled","prompt-result-refused","prompt-timeout","unlocked-for-client"))
class StandardRefusal(ValueError):
    def __init__(self,status):
        self.status=status if status in CLIENT_STATUSES | {"client-exit"} else "carrier-gate"
        super().__init__("resident-standard-vault-action-refused")
def refusal_projection(error):
    # OS errors and arbitrary child output are never reflected into diagnostics.
    result={"status":"resident-standard-vault-action-refused","secret_output":False,
        "provider_invocation":False,"resident_key_readiness_proven":False,
        "phase":PHASE if PHASE in common.PHASES else "arguments","predicate":"carrier-gate"}
    if isinstance(error,StandardRefusal):result["predicate"]=error.status
    elif isinstance(error,common.ClosedRefusal):
        with_predicate=common.refusal_projection(error)
        result["predicate"]=with_predicate["predicate"]
    return result
def observe(observer,until):
    environment={"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus",
        vault.DEADLINE_VARIABLE:str(until),"LC_ALL":"C"}
    answer=subprocess.run([observer,"--standard-service-metadata"],env=environment,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=budget(until),check=False)
    if answer.returncode!=0:common.observer_refusal(answer)
    require(0<len(answer.stdout)<=16384)
    value=vault.standard_observation(json.loads(answer.stdout,object_pairs_hook=resident.unique))
    vault.expected_processes(value)
    return value
def client_status(answer):
    try:
        require(0<len(answer.stdout)<=4096)
        value=json.loads(answer.stdout,object_pairs_hook=resident.unique)
        require(type(value) is dict and set(value)=={"schema","status"}
            and value["schema"]=="omux-standard-vault-unlock-result-v1"
            and type(value["status"]) is str and value["status"] in CLIENT_STATUSES)
        require(answer.returncode==(0 if value["status"]=="unlocked-for-client" else 125))
        return value["status"]
    except (ValueError,KeyError,TypeError):
        raise StandardRefusal("client-exit") from None
def unlock(before,selected,client,until):
    vault.standard_schema(selected);vault.standard_unlockable(before)
    require(before==selected["expected"])
    vault.expected_processes(before)
    broker,manager,secret=(before[name] for name in ("broker","manager","secret_service"))
    # Public identity argv only.  The selected opaque collection stays on a private metadata pipe.
    arguments=[client,"--standard-secret-service-unlock",str(broker["pid"]),str(broker["start_ticks"]),
        manager["owner"],str(manager["pid"]),str(manager["start_ticks"]),
        secret["owner"],str(secret["pid"]),str(secret["start_ticks"])]
    environment={"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus",
        vault.DEADLINE_VARIABLE:str(until),"LC_ALL":"C"}
    try:
        answer=subprocess.run(arguments,env=environment,input=before["default_collection"].encode("ascii"),
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=budget(until,1200),check=False)
    except subprocess.TimeoutExpired:
        raise StandardRefusal("deadline") from None
    status=client_status(answer)
    if status!="unlocked-for-client":raise StandardRefusal(status)
    vault.expected_processes(before)
    return status
def compare_after(before,after):
    vault.standard_observation(before);vault.standard_observation(after)
    require(all(before[key]==after[key] for key in ("broker","manager","secret_service","provider",
        "default_collection","default_exists")))
    # Locked is observed on this distinct observer connection.  Unlock may be
    # per-client, so preserving True here is honest and never proves daemon readiness.
    require(type(after["locked"]) is bool)
def main(argv=None):
    global PHASE
    PHASE="arguments"
    arguments=sys.argv[1:] if argv is None else argv
    require(len(arguments)==3 and arguments[0] in ("observe","unlock"))
    action,observer,client=arguments
    PHASE="deadline";until=deadline(os.environ)
    PHASE="private-input";selected=vault.standard_schema(private_manifest())
    require(selected["purpose"]=={"observe":"observe-standard-vault","unlock":"unlock-standard-vault"}[action])
    PHASE="before-observation";before=observe(observer,until)
    if action=="unlock":
        PHASE="unlock";status=unlock(before,selected,client,until)
        PHASE="after-observation";after=observe(observer,until)
        PHASE="observation-stability";compare_after(before,after)
    else:
        PHASE="after-observation";after=observe(observer,until)
        PHASE="observation-stability";require(before==after);status="not-dispatched"
    output={"schema":"omux-resident-standard-vault-action-v1","purpose":selected["purpose"],
        "observation":after,"unlock_dispatched":action=="unlock","client_status":status,
        "unlock_effect_scope":"helper-connection-verified/resident-readiness-unproved" if action=="unlock" else "not-dispatched",
        "unchanged_service_owner":True,"unchanged_default_collection":True,"factor_material_access":False,
        "provider_invocation":False,"omux_datastore_access":False,"omux_wrapping_key_regeneration":False,
        "resident_key_readiness_proven":False,"resident_custody_proven":False,"normal_os_unlock_passed":action=="unlock","native_support":False}
    PHASE="metadata-output";retain(output)
    print(json.dumps({"status":"standard-vault-metadata-observed" if action=="observe" else "standard-os-unlock-client-observed",
        "provider":after["provider"],"default_exists":after["default_exists"],"locked":after["locked"],
        "unlock_effect_scope":output["unlock_effect_scope"],"resident_key_readiness_proven":False,
        "provider_invocation":False},sort_keys=True))
    return 0
if __name__=="__main__":
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
        print(json.dumps(refusal_projection(error),sort_keys=True));sys.exit(125)

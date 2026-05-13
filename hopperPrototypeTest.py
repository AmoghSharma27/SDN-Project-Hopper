# Author: Amogh Sharma, Manveer Singh Pabla
# Date: 24-03-2026
#
# @brief: This file is a testing class to check the functionality of the hopperPrototype class.

from importlib.resources import path

from cleanData import get_paths
from graph import LoginGraph
from hopperPrototype import Hopper

def evaluate(logingraph: LoginGraph):
    # Populate the graph
    # logingraph = LoginGraph()
    # paths = get_paths()
    # for t, src_user, dst_user, src_host, dst_host in paths:
    #     logingraph.add_login(t, src_user, dst_user, src_host, dst_host)
    graph = logingraph.get_graph()

    # Variables to store some statistics about the suspicious paths found
    total_suspicious_paths = 0
    credential_switching_count = 0
    privilege_escalation_count = 0
    both_count = 0
    longest_path_length = 0
    longest_path = None

    hopper = Hopper(graph)
    suspicious_paths = hopper.detect()

    for path in suspicious_paths:
        reason = path["reason"]
        
        # Update statistics
        total_suspicious_paths += 1
        if reason == "Credential Switching":
            credential_switching_count += 1
        elif reason == "Privilege Escalation":
            privilege_escalation_count += 1
        elif reason == "Credential Switching and Privilege Escalation":
            both_count += 1

        if len(path["path"]) > longest_path_length:
            longest_path_length = len(path["path"])
            longest_path = path

        print(f"[Hopper] {reason} detected.")
        print(f"         Path:  {path['path_string']}")
        print(f"         Users: {path['src_user']} -> {path['dst_user']}")
        print(f"         Time:  {path['start_timestamp']} to {path['end_timestamp']}")
        print(f"         Credentials Possibly Compromised: {', '.join(sorted(path['credentials_used']))}")
        print()

    # Print the statistics for the suspicious paths found
    print(f"\nTotal Suspicious Paths Detected: {total_suspicious_paths}")
    try:
        print(f"Credential Switching: {credential_switching_count} ({credential_switching_count/total_suspicious_paths*100:.2f}%)")
        print(f"Privilege Escalation: {privilege_escalation_count} ({privilege_escalation_count/total_suspicious_paths*100:.2f}%)")
        print(f"Credential Switching and Privilege Escalation: {both_count} ({both_count/total_suspicious_paths*100:.2f}%)")
    except ZeroDivisionError:
        print("No Suspicious Paths found.")

    print(f"\nLongest Suspicious Path Length: {longest_path_length}")
    if longest_path:
        print(f"Longest Suspicious Path: {longest_path['path_string']}")
        print(f"Users Involved:- Src:{longest_path['src_user']} -> Dst:{longest_path['dst_user']}")
        print(f"Time: {longest_path['start_timestamp']} to {longest_path['end_timestamp']}")
        print(f"Credentials Possibly Compromised: {', '.join(sorted(longest_path['credentials_used']))}")


if __name__ == "__main__":
    # for testing purposes, we can directly call the evaluate function with a graph populated from the cleanData file. 
    logingraph = LoginGraph()
    paths = get_paths()
    for t, src_user, dst_user, src_host, dst_host in paths:
        logingraph.add_login(t, src_user, dst_user, src_host, dst_host)
    evaluate(logingraph)
# Author: Amogh Sharma
# Date: 24-03-2026
#
#
# @brief: This file defines the Hopper class which contains the logic for detecting suspicious paths given in the graph.
# It utilizes the hopper detection algorithm to detect lateral movement attacks by matching these two main properties:
# 1. Credential Switching: A user logs into a particular host and then logs into another host using a different credential. This is often a sign of lateral movement.
# 2. Privilege Escalation: A user logs into a host they they never had access to.
# For this project, we will assume that the src host a user logs in from is the level of access they have. The destination host they log into
# is added to their access level if the weight of the edge is within the access threshold.

import networkx as nx
import numpy as np

class Hopper:

    # This function initializes the different private variables used by the Hopper class
    # These variables are:
    # -> self.graph: A DiGraph constructed from the login data in the auth folder
    #
    # -> self.access_threshold: A range of values that is used as a threshold which determines if the weight of an edge means that a user 
    #                           has access to the destination machine.
    #   
    # -> self.multi_edge_paths: A list containing dictionaries, which have information regarding maths spanning multiple edges and users, used for the
    #                           main detection logic. The variable is of the form [{start_user, end_user, hosts, path, path_string, 
    #                           start_timestamp, end_timestamp}, {}, ...], where the keys are self-explanatory and the values are the respective data for that path.    
    #
    # -> self.not_benign_paths: This is a list of paths that are not considered benign. It is populated by the benign_checker() method, 
    #                           which checks if the weights of the edges in the path are within the access threshold. If they are not, 
    #                           then the path is added to this list.
    #
    # -> self.suspicious_paths: This is a list of dictionaries of the form: [{start_user, end_user, hosts, path, path_string,  
    #                           start_timestamp, end_timestamp}, {}, ...], which gets populated as the Hopper class' detect() method after  
    #                           it finds all malicious lateral movement within the given login graph. Its data is of the same form as in self.multi_edge_paths.
    #
    # -> self.user_access_levels: This is a dictionary of the form - {"user name@domain": (host1, host2, ...), ....}, where the keys are the user
    #                             names and the values are sets of hosts which the respective users have initial access to.
    #
    # -> self.MAX_PATH_LENGTH: This is the maximum path length that we want to consider for our detection. Paths longer than this are not considered.
    #
    # -> self.MIN_PATH_LENGTH: This is the minimum path length that we want to consider for our detection. Paths shorter than this are not considered.
    #
    def __init__(self, graph):
        self.graph = graph
        self.access_threshold = self.set_access_threshold()
        self.multi_edge_paths = []
        self.not_benign_paths = []
        self.suspicious_paths = []
        self.user_access_levels = {}
        self.MAX_PATH_LENGTH = 10
        self.MIN_PATH_LENGTH = 2

    # Main method that calls the different helper methods to detect suspicious paths in the graph and returns 
    # a list of dictionaries with all the relevant information about these paths.
    def detect(self):
        print("[Hopper] Detecting suspicious activity...")
        self.populate_user_access_levels()
        self.populate_paths()

        self.benign_checker()
        self.detect_credential_switching()
        self.detect_privilege_escalation()

        # Remove duplicates from suspicious paths
        self.filter_duplicate_paths()

        # Filter out sub-paths that are already contained in longer paths with the same reason.
        self.filter_redundant_paths()

        # Filter out paths that are seen twice due to having Credential Switching and Privilege Escalation as reasons.
        self.combine_path_reasons()
        return self.suspicious_paths
    
    # This method is used to set the access threshold for users based on the edge weights in the graph.
    # The weights represent how often the edge has been seen.
    def set_access_threshold(self):
        weights = np.array([data['weight'] for src, dst, data in self.graph.edges(data=True)])

        # Find threshold by getting the Interquartile Range of the array of weights
        if weights.size > 0:
            q3, q1 = np.percentile(weights, [75, 25])
            return range(round(q1), round(q3 + 1))
        else:
            # If weights does not exist, all paths are outside the threshold
            return range(0, 0)
        
    def benign_checker(self):
        for path in self.multi_edge_paths:
            if len(path["hosts"]) < self.MIN_PATH_LENGTH or len(path["hosts"]) > self.MAX_PATH_LENGTH:
                continue
        
            for (src, dst, data) in path["path"]:
                weight = data.get("weight", 0)

                if weight not in self.access_threshold:
                    self.not_benign_paths.append(path)
            
    
    # This method populates the self.user_access_levels dictionary based on the graph. 
    # It is required to be ran before the privilege escalation detection.
    def populate_user_access_levels(self):
        # Traverse the graph
        for src, dst, data in self.graph.edges(data=True):
            src_user = data.get('src_user')
            weight = data.get('weight')

            # If this is the first time we are seeing the user, and the weight of the edge is within the access threshold, 
            # we can set their access level to be the two hosts in this edge.
            if src_user not in self.user_access_levels:
                self.user_access_levels[src_user] = set([src])
                if weight in self.access_threshold:
                    self.user_access_levels[src_user].add(dst)

            # Otherwise, if we have seen this user before and the weight of the edge is within the access threshold, 
            # we update their access level to include the two hosts in this edge.
            elif src_user in self.user_access_levels:
                self.user_access_levels[src_user].add(src)
                if weight in self.access_threshold: 
                    self.user_access_levels[src_user].add(dst)

    # Function to populate the multi_edge_paths variable
    def populate_paths(self):

        # Sort all edges by timestamp so chains are built chronologically
        all_edges_sorted = sorted(
            self.graph.edges(data=True),
            key=lambda e: e[2].get("time", 0)
        )

        # Index paths by (tail_host, tail_user) for O(1) lookup instead of scanning the whole list again and again per edge.
        # Each key maps to a list of paths that end at that host with that user. They are candidates to be extended.
        path_index = {}

        # Traverse the graph until all edges have been visited
        for src, dst, data in all_edges_sorted:
            # Store all the data we need from this edge in variables
            curr_edge_src_user = data["src_user"]
            curr_edge_dst_user = data["dst_user"]
            curr_edge_timestamp = data["time"]
            curr_edge_src_host = src
            curr_edge_dst_host = dst
            
            # Look up all existing paths whose tail matches this edge's entry point
            lookup_key = (curr_edge_src_host, curr_edge_src_user)
            candidate_paths = path_index.get(lookup_key, [])
            
            # Find all branching paths this edge can extend
            # A path is matched if:
            # -> Its tail host is the same as the src host of the current edge
            # -> Its dst user is the same as the src user of the current edge
            # -> The current edge's dst host is not already in the path
            # -> The length of the path is less than the max chain length
            matching_paths = []
            for path in candidate_paths:
                tail_host = path["hosts"][-1]
                tail_user = path["dst_user"]
                if tail_host == curr_edge_src_host and tail_user == curr_edge_src_user and curr_edge_dst_host not in path["hosts"] and len(path["hosts"]) < self.MAX_PATH_LENGTH:
                    matching_paths.append(path)

            # Extend existing paths whose tail hosts match this edge's src host
            if matching_paths:
                for path in matching_paths:
                    # Create an extended path by adding this edge to the end of the path
                    extended_path = {
                        "src_user": path["src_user"],
                        "dst_user": curr_edge_dst_user,
                        "hosts": list(path["hosts"]) + [curr_edge_dst_host],
                        "path": list(path["path"]) + [(curr_edge_src_host, curr_edge_dst_host, data)],
                        "path_string": path["path_string"] + f" -> {{{curr_edge_dst_host}}}",
                        "credentials_used": set(path["credentials_used"]) | {curr_edge_src_user, curr_edge_dst_user},
                        "start_timestamp": path["start_timestamp"],
                        "end_timestamp": curr_edge_timestamp
                    }
                    self.multi_edge_paths.append(extended_path)

                    # Update the index with this new path, so it can be extended by future edges
                    path_index.setdefault((curr_edge_dst_host, curr_edge_dst_user), []).append(extended_path)
            
            # Start a new path from this edge if it doesn't match any existing path, and the src user is not a well known system user.
            # Other edges that have system users may be added to paths as they may indicate credential switching.
            elif not matching_paths and not self.is_system_user(curr_edge_src_user):
                new_path = {
                    "src_user": curr_edge_src_user,
                    "dst_user": curr_edge_dst_user,
                    "hosts": [curr_edge_src_host, curr_edge_dst_host],
                    "path": [(curr_edge_src_host, curr_edge_dst_host, data)],
                    "path_string": f"{{{curr_edge_src_host}}} -> {{{curr_edge_dst_host}}}",
                    "credentials_used": {curr_edge_src_user, curr_edge_dst_user},
                    "start_timestamp": curr_edge_timestamp,
                    "end_timestamp": curr_edge_timestamp
                }
                self.multi_edge_paths.append(new_path)

                # Update the index with this new path, so it can be extended by future edges
                path_index.setdefault((curr_edge_dst_host, curr_edge_dst_user), []).append(new_path)

    # Property #1: Path contains 1+ logins that use new credentials.
    def detect_credential_switching(self):
        # Traverse the list of paths
        for path in self.not_benign_paths:
            global_src_user = path["src_user"]
            global_dst_user = path["dst_user"]

            # Ignore well known system users
            if self.is_system_user(global_src_user):
                continue

            # If the credentials used in this path are more than 1, and the src and dst users of the path are different, then this is a suspicious path with credential switching.
            if len(path["credentials_used"]) > 1:
                # Create a dictionary with all the relevant information about this path and add it to the list of suspicious paths.
                sus_path = {
                    "src_user": global_src_user,
                    "dst_user": global_dst_user,
                    "hosts": path["hosts"],
                    "path": path["path"],
                    "path_string": path["path_string"],
                    "credentials_used": path["credentials_used"],
                    "start_timestamp": path["start_timestamp"],
                    "end_timestamp": path["end_timestamp"],
                    "reason": "Credential Switching"
                }
                self.suspicious_paths.append(sus_path)


    # Property #2: Path accesses a machine that a previous user did not previously have legitmate access to.
    def detect_privilege_escalation(self):
        # Traverse the list of paths
        for path in self.not_benign_paths:
            global_src_user = path["src_user"]

            # Check if the path has a different source and destination user
            dst_host = path["hosts"][-1]

            # Ignore well known system users
            if self.is_system_user(global_src_user):
                continue

            # Check if the destination user has access to the destination host
            if dst_host not in self.user_access_levels.get(global_src_user, set()) and len(path["hosts"]) > 1:
                # If not, it's a potential privilege escalation
                sus_path = {
                    "src_user": global_src_user,
                    "dst_user": path["dst_user"],
                    "hosts": path["hosts"],
                    "path": path["path"],
                    "path_string": path["path_string"],
                    "credentials_used": path["credentials_used"],
                    "start_timestamp": path["start_timestamp"],
                    "end_timestamp": path["end_timestamp"],
                    "reason": "Privilege Escalation"
                }
                self.suspicious_paths.append(sus_path)

    # Method to filter out duplicate paths. Two paths are duplicates if they have the same src user, dst user, hosts, path string and reason.
    def filter_duplicate_paths(self):
        # Keep track of seen paths using a set of tuples containing the relevant information to identify duplicates. 
        # If a path is not in the seen set, we add it to the unique paths list and add its identifying information to the seen set. 
        seen = set()
        unique_paths = []
        for path in self.suspicious_paths:
            key = (path["src_user"], path["dst_user"], path["path_string"], path["reason"])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)

        # Finally, we update self.suspicious_paths to be the list of unique paths.
        self.suspicious_paths = unique_paths

    # Method to filter out paths that are sub-paths of other longer paths. 
    # For example, if we have a path A -> B -> C that is suspicious, and we also have a path A -> B that is suspicious with the same reason, 
    # then we filter out the path A -> B.
    def filter_redundant_paths(self):
        all_path_strings = {p["path_string"] for p in self.suspicious_paths}
        non_redundant_paths = []
        for path in self.suspicious_paths:
            curr_path_string = path["path_string"]

            # A path is redundant if any other path string starts with it, but is longer
            is_subpath = False
            for other in all_path_strings:
                if other.startswith(curr_path_string) and other != curr_path_string:
                    is_subpath = True
                    break
            
            # If this path is not a sub-path of any other path, we add it to the list of non-redundant paths.
            if not is_subpath:
                non_redundant_paths.append(path)

        # Update the suspicious paths with the non-redundant paths.
        self.suspicious_paths = non_redundant_paths

    # This method combines duplicate paths that have different reasons (Credential Switching and Privilege Escalation) into one path with the combined 
    # reason "Credential Switching and Privilege Escalation".
    def combine_path_reasons(self):
        final_paths = []

        # For each path in self.suspicious_paths, we check if another path exists where the only difference between the two paths is the reson.
        # If such a path exists, we combine the two paths into one path with the reason "Credential Switching and Privilege Escalation".
        for path in self.suspicious_paths:
            if path["reason"] == "Credential Switching":
                # Check if there is a path with the same path string but reason Privilege Escalation
                has_escalation = False
                for p in self.suspicious_paths:
                    # Make sure p is same as path except for the reason.
                    if p["path_string"] == path["path_string"] and p["src_user"] == path["src_user"] and p["dst_user"] == path["dst_user"] and len(p["path"]) == len(path["path"]) and p["reason"] == "Privilege Escalation":
                        has_escalation = True
                        break

                if has_escalation:
                    # If yes, we combine the reasons into one: "Credential Switching and Privilege Escalation"
                    combined_path = path.copy()
                    combined_path["reason"] = "Credential Switching and Privilege Escalation"
                    final_paths.append(combined_path)
                else:
                    final_paths.append(path)

            # If the path's reason is Privilege Escalation, and a path identical to it exists with the reason Credential Switching, 
            elif path["reason"] == "Privilege Escalation":
                # Check if there is a path with the same path string but reason Credential Switching
                has_switching = False
                for p in self.suspicious_paths:
                    if p["path_string"] == path["path_string"] and p["src_user"] == path["src_user"] and p["dst_user"] == path["dst_user"] and len(p["path"]) == len(path["path"]) and p["reason"] == "Credential Switching":
                        has_switching = True
                        break
                if not has_switching:
                    final_paths.append(path)

        # Update the suspicious paths with the final paths after combining the reasons.
        self.suspicious_paths = final_paths

    def is_system_user(self, user):
        if user.startswith("SYSTEM") or user.startswith("LOCAL SERVICE"):
            return True
        return False
# References
# 1. Ho, G., Dhiman, M., Akhawe, D., Paxson, V., Savage, S., Voelker, G. M., & Wagner, D. (2021). 
# Hopper: Modeling and detecting lateral movement. In Proceedings of the 30th USENIX Security Symposium (USENIX Security 21) 
# (pp. 3093–3110). USENIX Association. https://www.usenix.org/conference/usenixsecurity21/presentation/ho
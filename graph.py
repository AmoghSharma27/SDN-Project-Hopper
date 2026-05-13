
# Author: Miriam Okutuo
# Date: 23-03-2026
# @brief: This file constructs login graphs and uses it to identify suspicious login patterns

import networkx as nx


class LoginGraph:
    def __init__(self):
        self.net = nx.DiGraph() # login events have direction. src_host -> dst_host, hence the use of directed graph

    # @brief: this function builds the graph incrementally one login at a time
    def add_login(self, t, src_user, dst_user, src_host, dst_host):

        '''check if there's been a login between two hosts before, 
           if yes, increment the communication count
           if no, simply create a new edge (src_host, dst_host), record the time it first occurred
           and init the comunication count to 1. i.e a fresh login relationship
        '''
        if self.net.has_edge(src_host, dst_host): 
            self.net[src_host][dst_host]['weight'] += 1 # increment communication count and track all users seen on this path for credential switching detection
            self.net[src_host][dst_host]['users'].append(src_user)

        else:
            self.net.add_edge(src_host, dst_host, time=t, weight=1, src_user=src_user, dst_user=dst_user, users=[src_user]) # new edge.



    def get_graph(self):

        '''
        simply return the full graph object.
        this is what is called to run Hopper logic on
        '''
        return self.net
    
    def print_graph(self):
        '''
        helper function to print the graph in a readable format. 
        '''
        g = self.get_graph()
        print(list(g.edges(data=True)))
        print(f"Number of nodes: {g.number_of_nodes()} and Number of edges: {g.number_of_edges()}")
        


# sanity check => run with python3 graph.py
def main():
    from cleanData import get_paths # import data from cleanData.py file

    paths = get_paths()
    login_graph = LoginGraph()
    for t, src_user, dst_user, src_host, dst_host in paths:
        login_graph.add_login(t, src_user, dst_user, src_host, dst_host)
    
    login_graph.print_graph()


if __name__ == "__main__":
    main()



# References
# https://networkx.org/documentation/stable/tutorial.html
# https://networkx.org/documentation/networkx-2.3/reference/classes/generated/networkx.DiGraph.number_of_edges.html
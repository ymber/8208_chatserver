from networkx.algorithms import bipartite
from networkx.algorithms.community import greedy_modularity_communities
from collections import defaultdict
from datetime import datetime, timedelta
import networkx as nx
import matplotlib.pyplot as plt

class BotDetection:
    def __init__(self):
        self.graph = nx.Graph()

    def build_graph(self, events):
        accounts = set()
        ips = set()
        
        interactions_per_account = defaultdict(int)
        last_interaction_time = defaultdict(lambda: datetime.min)

        for timestamp, account, ip in events:
            accounts.add(account)
            ips.add(ip)
            interactions_per_account[account] += 1
            last_interaction_time[account] = max(last_interaction_time[account], timestamp)
            self.graph.add_edge(account, ip, timestamp=timestamp)

        return self.graph, accounts, ips, interactions_per_account, last_interaction_time

    def create_projection(self, graph, account_nodes):
        account_nodes = [n for n in graph.nodes if n in account_nodes]
        weighted_proj = nx.bipartite.weighted_projected_graph(graph, account_nodes)

        return weighted_proj

    def create_clusters(self, graph):
        communities = greedy_modularity_communities(graph)

        return communities

    def analyze_communities(self, communities):
        community_dict = defaultdict(list)
        
        for i, community in enumerate(communities):
            for account in community:
                community_dict[account].append(i)

        return community_dict
    
    def create_events(self):
        events = [
            (datetime(2024, 3, 19, 10, 2, 30), "account1", "ip1"), 
            (datetime(2024, 3, 19, 10, 6, 20), "account2", "ip1"), 
            (datetime(2024, 3, 19, 10, 3, 50), "account3", "ip1"),
            (datetime(2024, 3, 19, 11, 5, 0), "account4", "ip2"),
            (datetime(2024, 3, 19, 11, 20, 0), "account5", "ip2"),
            (datetime(2024, 3, 19, 10, 0, 0), "account6", "ip2"),
            (datetime(2024, 3, 19, 12, 20, 30), "account7", "ip9"),
            (datetime(2024, 3, 19, 10, 0, 0), "account8", "ip3"),
            (datetime(2024, 3, 19, 17, 4, 0), "account9", "ip4"),
            (datetime(2024, 3, 19, 10, 20, 20), "account10", "ip3")]
        
        return events
    
    def create_plot(self, graph, accounts, interactions_per_account):
        node_sizes = [interactions_per_account[account] * 100 for account in accounts]
        pos = nx.bipartite_layout(graph, accounts)

        plt.figure(figsize=(10, 5))
        nx.draw(graph, pos, nodelist=accounts, with_labels=True, node_size=node_sizes)
        plt.show()

    def main(self):
        events = self.create_events()
        graph, accounts, ips, interactions_per_account, last_interaction_time = self.build_graph(events)
        weighted_projection = self.create_projection(graph, accounts)
        communities = self.create_clusters(weighted_projection)
        bot_communities = self.analyze_communities(communities)
        self.create_plot(graph, accounts, interactions_per_account)


if __name__ == "__main__":
    bd = BotDetection()
    bd.main()


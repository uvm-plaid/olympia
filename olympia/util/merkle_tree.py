import hashlib
from typing import List, Tuple

class Node:
    def __init__(self, data=None, left=None, right=None):
        self.data: bytes = data
        self.left: Node = left
        self.right: Node = right
        self.combination = self.left.combination + self.right.combination if self.left and self.right else self.data

    def hash(self):
        if self.data is not None:
            return hashlib.sha256(self.data).hexdigest()
        left_hash = self.left.hash()
        right_hash = self.right.hash() if self.right else None
        return hashlib.sha256((left_hash + right_hash).encode()).hexdigest()
    
    def __str__(self):
        return f"Node({self.data}, {self.combination})"

class MerkleTree:
    def __init__(self):
        self.root = None
        self.levels: List[List[Node]] = [[]]
        self.count: int = 0

    def add_data(self, data):
        node = Node(data)
        self.levels[0].append(node)
        self.count += 1
        i = 0
        bubble_changes = False
        while i < len(self.levels):
            if len(self.levels[i]) % 2 == 0:
                node = Node(None, self.levels[i][-2], self.levels[i][-1])
                if i + 1 >= len(self.levels):
                    self.levels.append([])
                if len(self.levels[i + 1]) > 0 and self.levels[i + 1][-1] is self.levels[i][-2] or bubble_changes:
                    self.levels[i + 1][-1] = node
                    bubble_changes = True
                else:
                    self.levels[i + 1].append(node)
            elif len(self.levels) > i + 1:
                if bubble_changes:
                    self.levels[i + 1][-1] = node
                else:
                    self.levels[i + 1].append(node)
            i += 1
        self.root = self.levels[-1][-1] if self.levels[-1] else None


    def get_root_hash(self):
        return self.root.hash() if self.root else None

    def get_path(self, index):
        path = []
        for i, level in enumerate(self.levels):
            if index < len(level):
                node = level[index]
                try:
                    neighbor = level[index + 1] if index % 2 == 0 else level[index - 1]
                except IndexError:
                    neighbor = None

                path.append((node, neighbor, 'left' if index % 2 == 0 else 'right'))
                index //= 2
        return path
    
    def get_verification_tree(self, index):
        path = self.get_path(index)
        return VerificationTree(index, path)

    def __str__(self):
        line = "-------------------------------------------"
        body = ""
        for i, level in enumerate(self.levels):
            body += f'Level: {i}\n'
            body += f'{[a.combination for a in level]}\n'
        return line + body + line

class VerificationTree:
    def __init__(self, index: int, path: List[Tuple[Node, Node, str]]):
        self.root_hash = path[-1][0].hash()
        self.index = index
        self.path = path

    def verify(self, data):
        verification_node = Node(data)
        for node, neighbor, direction in self.path:
            assert verification_node.hash() == node.hash(), "Verification failed"
            if neighbor is not None:
                verification_node = Node(None, neighbor, verification_node) if direction == 'right' else Node(None, verification_node, neighbor)
        
def test_merkle_tree():
    tree = MerkleTree()
    for i in range(22):
        tree.add_data(bytes(i))

    print(tree)
    path = [(node.combination, neighbor.combination if neighbor != None else None, direction) for node, neighbor, direction in tree.get_path(21)]
    path.reverse()
    print(path)

    for i in range(22):
        verification_tree = VerificationTree(i, tree.get_path(i))
        verification_tree.verify(bytes(i))



    
    